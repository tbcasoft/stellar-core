// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/TCPPeer.h"
#include "database/Database.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "medida/meter.h"
#include "medida/metrics_registry.h"
#include "overlay/LoadManager.h"
#include "overlay/OverlayManager.h"
#include "overlay/OverlayMetrics.h"
#include "overlay/PeerManager.h"
#include "overlay/StellarXDR.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/format.h"
#include "xdrpp/marshal.h"

#include "overlay/PeerAuth.h" //Needed to derive shared secret key from peer
#include "crypto/SHA.h" //Needed to hash shared secred key

using namespace soci;

namespace stellar
{

using namespace std;

///////////////////////////////////////////////////////////////////////
// TCPPeer
///////////////////////////////////////////////////////////////////////

const size_t TCPPeer::BUFSZ;

TCPPeer::TCPPeer(Application& app, Peer::PeerRole role,
                 std::shared_ptr<TCPPeer::SocketType> socket)
    : Peer(app, role), mSocket(socket)
{
}

TCPPeer::pointer
TCPPeer::initiateSynch(Application& app, PeerBareAddress const& address)
{

    CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - start" << address.toString();
    assert(address.getType() == PeerBareAddress::Type::IPv4);
    assertThreadIsMain();
    auto bufferedAsioSocket = make_shared<SocketType>(app.getClock().getIOContext(), BUFSZ);
    /*
    The 1st time a remote node receives a request from us:
    - It will create a TCPPeer (role REMOTE_CALLED_US) to represent us.  See PeerDoor::handleKnock(socket).
    */
    auto result = make_shared<TCPPeer>(app, WE_CALLED_REMOTE,  bufferedAsioSocket);  //Role WE_CALLED_REMOTE will force peer to send HELLO back to us.
    result->mAddress = address;

    //== 1st step to connect to peer is to send a HELLO msg
    StellarMessage hello;
    hello.type(HELLO);
    Hello& eloXdr = hello.hello();
    eloXdr.ledgerVersion = app.getConfig().LEDGER_PROTOCOL_VERSION;
    eloXdr.overlayMinVersion = app.getConfig().OVERLAY_PROTOCOL_MIN_VERSION;
    eloXdr.overlayVersion = app.getConfig().OVERLAY_PROTOCOL_VERSION;
    eloXdr.versionStr = app.getConfig().VERSION_STR;
    eloXdr.networkID = app.getNetworkID();
    eloXdr.listeningPort = app.getConfig().PEER_PORT;
    eloXdr.peerID = app.getConfig().NODE_SEED.getPublicKey();
    eloXdr.cert = result->getAuthCert();
    eloXdr.nonce = result->mSendNonce;

    AuthenticatedMessage amsg;
    amsg.v0().message = hello;
    //For HELLO, the receiving peer with not validate the authenticaticity of msg by checking the HMAC value
    xdr::msg_ptr xdrBytes(xdr::xdr_to_msg(amsg));
    
    //== All we have done so far is instantiate a representation of remote peer.  Lets start to create the communication pipe.
    asio::io_context io_context;
    asio::ip::tcp::socket basicAsioTcpSocket(io_context);
    asio::ip::tcp::resolver resolver(io_context);
    asio::ip::tcp::endpoint endpoint = asio::connect(basicAsioTcpSocket, resolver.resolve("127.0.0.1", "11630"));
    size_t request_length = xdrBytes->raw_size();
    //following blocks until the full request has been written to socket
    asio::write(basicAsioTcpSocket, asio::buffer(xdrBytes->raw_data(), request_length));

    //== now read response on connected socket
    std::vector<uint8_t> respHttpHdr; //we just want 4 bytes which represents the http response hdr
    respHttpHdr.resize(HDRSZ);
    size_t len;
    try
    {
        asio::error_code ec_hdr;
        //blocks until we get enough respinse data is read or error occurs.  
        //*Note: unlike read(), this behavior will not throw error if the data does not
        //meet the buffer size.
        len = basicAsioTcpSocket.read_some(asio::buffer(respHttpHdr, HDRSZ), ec_hdr); 
        if (ec_hdr == asio::error::eof) {
            throw std::runtime_error("unexpected behavior.  Expecting peer to send HELLO response instead it close the connection");
        } else if (ec_hdr) {
            throw std::runtime_error(fmt::format("asio error msg while reading the response header: {}", ec_hdr.message()) );
        }

        if (len != HDRSZ) {
            throw std::runtime_error(fmt::format("Not able to read enough bytes for Http Response Header, num of bytes read: {}", len) );
        } 

    } catch (std::exception& e) {
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception reading response, error: {}", e.what()) );
    }

    //== derive response body len from the response header
    size_t httpRespBodyLen = static_cast<size_t>(respHttpHdr[0]);
    httpRespBodyLen &= 0x7f; // clear the XDR 'continuation' bit
    httpRespBodyLen <<= 8;
    httpRespBodyLen |= respHttpHdr[1]; //processing 2nd bit
    httpRespBodyLen <<= 8;    
    httpRespBodyLen |= respHttpHdr[2]; //processing 3rd bit
    httpRespBodyLen <<= 8;
    httpRespBodyLen |= respHttpHdr[3];  //processing 4th bit
    if (httpRespBodyLen <= 0 || httpRespBodyLen > MAX_MESSAGE_SIZE) {
        result->drop("drop remote peer as response is not valid", Peer::DropDirection::WE_DROPPED_REMOTE,
             Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch -- response from remote peer does not seem valid" \
                    " (note: dropped remote peer)." \
                    "  size of body length {}", httpRespBodyLen) );
    }

    CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - the response body length is: " << httpRespBodyLen;

    std::vector<uint8_t> respHttpBody;
    respHttpBody.resize(httpRespBodyLen);
    try {
        asio::error_code ec_body;
        size_t lenBytesReadForBody = basicAsioTcpSocket.read_some(asio::buffer(respHttpBody), ec_body);
        if (ec_body == asio::error::eof) {
            throw std::runtime_error("Peer closed connection while reading the response body.");
        } else if (ec_body) {
            throw std::runtime_error(fmt::format("asio error msg while reading the response body: {}", ec_body.message()) );
        }

        if (lenBytesReadForBody != httpRespBodyLen) {
            throw std::runtime_error(fmt::format("Not able to read enough bytes the response body, num of bytes read: {}", lenBytesReadForBody) );
        }

        xdr::xdr_get g(respHttpBody.data(), respHttpBody.data() + respHttpBody.size());
        AuthenticatedMessage am;
        xdr::xdr_argpack_archive(g, am);
        stellar::StellarMessage sm = am.v0().message;
        stellar::MessageType msgType = sm.type();
        CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received response from peer, messge type:" << msgType;
        if (msgType == stellar::MessageType::ERROR_MSG) {
            stellar::Error & error = sm.error();
            stellar::ErrorCode ec = error.code;
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - received error msg from peer, error code: {}, error msg: {}", ec, std::string{error.msg}) );
            
        } else if (msgType == stellar::MessageType::HELLO) {
            CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received hello response from peer."
                << "  Will now update peer's metadata and derive the mac key from peer's cert."
                ;
            stellar::Hello helloMsg = sm.hello();
            result->mRemoteOverlayMinVersion = helloMsg.overlayMinVersion;
            result->mRemoteOverlayVersion = helloMsg.overlayVersion;
            result->mRemoteVersion = helloMsg.versionStr;
            result->mPeerID = helloMsg.peerID;
            result->mRecvNonce = helloMsg.nonce;
            result->mSendMacSeq = 0;
            result->mRecvMacSeq = 0;

            //Derive shared key from remote peer used to authenticate each receive msg.  Inspired by Peer::recvHello()
            stellar::PeerAuth& pAuth = result->mApp.getOverlayManager().getPeerAuth();
            result->mSendMacKey = pAuth.getSendingMacKey(helloMsg.cert.pubkey, result->mSendNonce,
                                        result->mRecvNonce, result->mRole);
            result->mRecvMacKey = pAuth.getReceivingMacKey(helloMsg.cert.pubkey, result->mSendNonce,
                                            result->mRecvNonce, result->mRole);

            result->mState = GOT_HELLO; //transition the state for the remote peer
            /**  not working as ip is blank
            basicAsioTcpSocket.remote_endpoint().address()
            auto ip = result->getIP();
            result->mAddress = PeerBareAddress{ip, static_cast<unsigned short>(helloMsg.listeningPort)};
            **/
        } else {
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - hello msg of our sequence, received unexpected msg type {}", msgType) );
        }

    } catch (xdr::xdr_runtime_error& e) {
        //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "received corrupt XDR", Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling response, error: {}", e.what()) );
    } catch (std::exception& e) {
        //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling response, error: {}", e.what()) );
    }

    //Last step in handshake protocol, send AUTH(signed([0],keyAB)) where keyAB???
    StellarMessage authStellarMsg;
    authStellarMsg.type(AUTH);
    AuthenticatedMessage authAmsg;
    authAmsg.v0().message = authStellarMsg;
    authAmsg.v0().sequence = result->mSendMacSeq;
    authAmsg.v0().mac =
            hmacSha256(result->mSendMacKey, xdr::xdr_to_opaque(result->mSendMacSeq, authStellarMsg));
    ++result->mSendMacSeq;

    xdr::msg_ptr authXdrBytes(xdr::xdr_to_msg(authAmsg));
    size_t authRequest_length = authXdrBytes->raw_size();
    //following blocks until the full request has been written to socket
    size_t bytesWriiten = asio::write(basicAsioTcpSocket, asio::buffer(authXdrBytes->raw_data(), authRequest_length));

    //== now read response on connected socket
    std::vector<uint8_t> authRespHttpHdr; //we just want 4 bytes which represents the http response hdr
    authRespHttpHdr.resize(HDRSZ);

    try {
        asio::error_code ec_peer_auth;
        //blocks until we get enough respinse data is read or error occurs.  
        //*Note: unlike read(), this behavior will not throw error if the data does not
        //meet the buffer size.
        size_t bytesRead = basicAsioTcpSocket.read_some(asio::buffer(authRespHttpHdr), ec_peer_auth);   
        if (ec_peer_auth == asio::error::eof) {
            throw std::runtime_error("unexpected behavior.  Expecting peer to send AUTH response instead it close the connection");
        } else if (ec_peer_auth) {
            throw std::runtime_error(fmt::format("asio error msg while reading the response header: {}", ec_peer_auth.message()) );
        }
        if (bytesRead != HDRSZ) {
            throw std::runtime_error(fmt::format("Not able to read enough bytes for Http Response Header, num of bytes read: {}", bytesRead) );
        }    

        //== derive response body len from the response header
        size_t authRepBodyLen = static_cast<size_t>(authRespHttpHdr[0]);
        authRepBodyLen &= 0x7f; // clear the XDR 'continuation' bit
        authRepBodyLen <<= 8;
        authRepBodyLen |= authRespHttpHdr[1]; //processing 2nd bit
        authRepBodyLen <<= 8;    
        authRepBodyLen |= authRespHttpHdr[2]; //processing 3rd bit
        authRepBodyLen <<= 8;
        authRepBodyLen |= authRespHttpHdr[3];  //processing 4th bit
        if (authRepBodyLen <= 0 || authRepBodyLen > MAX_MESSAGE_SIZE) {
            result->drop("drop remote peer as auth response is not valid", Peer::DropDirection::WE_DROPPED_REMOTE,
                Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch -- auth response from remote peer does not seem valid" \
                        " (note: dropped remote peer)." \
                        "  size of body length {}", authRepBodyLen) );
        }
        CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - the response body length is: " << httpRespBodyLen;

        std::vector<uint8_t> authHttpBody;
        authHttpBody.resize(authRepBodyLen);
        try {
            asio::error_code ec_authbody;
            size_t lenBytesReadForAuthBody = basicAsioTcpSocket.read_some(asio::buffer(authHttpBody), ec_authbody);            
            if (ec_authbody == asio::error::eof) {
                throw std::runtime_error("Peer closed connection while reading the auth response body.");
            } else if (ec_authbody) {
                throw std::runtime_error(fmt::format("asio error msg while reading the auth response body: {}", ec_authbody.message()) );
            }

            if (lenBytesReadForAuthBody != authRepBodyLen) {
                throw std::runtime_error(fmt::format("Not able to read enough bytes the auth response body, num of bytes read: {}", lenBytesReadForAuthBody) );
            }

            xdr::xdr_get g(authHttpBody.data(), authHttpBody.data() + authHttpBody.size());
            AuthenticatedMessage authAM;
            xdr::xdr_argpack_archive(g, authAM);
            stellar::StellarMessage sm = authAM.v0().message;
            stellar::MessageType msgType = sm.type();
            CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received response from peer, messge type:" << msgType;
            switch(msgType)
            {
                case MessageType::AUTH: {
                    stellar::Auth & a = sm.auth();
                    result->mState = GOT_AUTH; //transition state for peer
                    break;                    
                }
                case MessageType::ERROR_MSG: {
                    stellar::Error & error = sm.error();
                    stellar::ErrorCode ec = error.code;
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - received err msg type for our auth request, error coe {}, error msg {}"
                        , ec, std::string{error.msg}) );    
                }
                default:
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - auth msg of our sequence, received unexpected msg type {}", msgType) );
            }

        } catch (xdr::xdr_runtime_error& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "received corrupt XDR", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling auth response, error: {}", e.what()) );
        } catch (std::exception& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling auth response, error: {}", e.what()) );
        }

    } catch (std::exception& e) {
        //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling peer auth response, error: {}", e.what()) );
    }

    //== if here, we have successfully sent "auth" request which means the remote peer will send us its peers list, lets read that info from open socket
    std::vector<uint8_t> peersRespHttpHdr; //we just want 4 bytes which represents the http response hdr
    peersRespHttpHdr.resize(HDRSZ);
    try{

        asio::error_code ec_peers_list;
        //blocks until we get enough respinse data is read or error occurs.  
        //*Note: unlike read(), this behavior will not throw error if the data does not
        //meet the buffer size.
        size_t bytesRead = basicAsioTcpSocket.read_some(asio::buffer(peersRespHttpHdr), ec_peers_list);   
        if (ec_peers_list == asio::error::eof) {
            throw std::runtime_error("unexpected behavior.  Expecting peer to send peer list response instead it close the connection");
        } else if (ec_peers_list) {
            throw std::runtime_error(fmt::format("asio error msg while reading the peers list response header: {}", ec_peers_list.message()) );
        }
        if (bytesRead != HDRSZ) {
            throw std::runtime_error(fmt::format("Not able to read enough bytes for peers list Http Response Header, num of bytes read: {}", bytesRead) );
        }  

        //== derive response body len from the response header
        size_t peersRespBodyLen = static_cast<size_t>(peersRespHttpHdr[0]);
        peersRespBodyLen &= 0x7f; // clear the XDR 'continuation' bit
        peersRespBodyLen <<= 8;
        peersRespBodyLen |= peersRespHttpHdr[1]; //processing 2nd bit
        peersRespBodyLen <<= 8;    
        peersRespBodyLen |= peersRespHttpHdr[2]; //processing 3rd bit
        peersRespBodyLen <<= 8;
        peersRespBodyLen |= peersRespHttpHdr[3];  //processing 4th bit  
        if (peersRespBodyLen <= 0 || peersRespBodyLen > MAX_MESSAGE_SIZE) {
            result->drop("drop remote peer as peers list response is not valid", Peer::DropDirection::WE_DROPPED_REMOTE,
                Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch -- peers list response from remote peer does not seem valid" \
                        " (note: dropped remote peer)." \
                        "  size of body length {}", peersRespBodyLen) );
        }

        CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - the peers list response body length is: " << peersRespBodyLen;
        std::vector<uint8_t> peersListHttpBody;
        peersListHttpBody.resize(peersRespBodyLen);
        try {

            asio::error_code ec_peerslist;
            size_t lenBytesReadForPeersBody = basicAsioTcpSocket.read_some(asio::buffer(peersListHttpBody), ec_peerslist);
            if (ec_peerslist == asio::error::eof) {
                throw std::runtime_error("Peer closed connection while reading the peers list response body.");
            } else if (ec_peerslist) {
                throw std::runtime_error(fmt::format("asio error msg while reading the peers list response body: {}", ec_peerslist.message()) );
            }

            if (lenBytesReadForPeersBody != peersRespBodyLen) {
                throw std::runtime_error(fmt::format("Not able to read enough bytes for the peers list response body, num of bytes read: {}", lenBytesReadForPeersBody) );
            }  

            xdr::xdr_get g(peersListHttpBody.data(), peersListHttpBody.data() + peersListHttpBody.size());
            AuthenticatedMessage peersListAM;
            xdr::xdr_argpack_archive(g, peersListAM);
            stellar::StellarMessage sm = peersListAM.v0().message;
            stellar::MessageType msgType = sm.type();
            CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received peers list response from peer, messge type:" << msgType;

            switch(msgType)
            {
                case MessageType::PEERS: {
                    xdr::xvector<stellar::PeerAddress, 100U> & peers = sm.peers();
                    size_t numOfPeers = sm.peers().size();
                    if (numOfPeers) {

                        for (stellar::PeerAddress peer : peers) {
                            auto address = PeerBareAddress{peer};
                            CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - remote peer is connected to stellar node ip: " 
                                << address.getIP() << ", port: " << address.getPort()
                                << ", to string: " << address.toString()
                                ;
                        }

                    } else {
                        CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received peers list respose but remote peer is not connected to any stellar node";
                    }

                    break;                    
                }
                case MessageType::ERROR_MSG: {
                    stellar::Error & error = sm.error();
                    stellar::ErrorCode ec = error.code;
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - received err msg type for our peer list response, error coe {}, error msg {}"
                        , ec, std::string{error.msg}) );    
                }
                default:
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - auth msg of our sequence, received unexpected msg type {}", msgType) );
            }

        } catch (xdr::xdr_runtime_error& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "received corrupt XDR", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling peers lisdt response, error: {}", e.what()) );
        } catch (std::exception& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling peers list response, error: {}", e.what()) );
        }

    }  catch (std::exception& e) {
        //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling peers list response, error: {}", e.what()) );
    }

    //== we now have an authenticated connection, lets send requests to it
    StellarMessage scpQuorumSetStellarMsg;
    scpQuorumSetStellarMsg.type(SCP_QUORUMSET);
    AuthenticatedMessage scpQuorumSetAmsg;
    scpQuorumSetAmsg.v0().message = scpQuorumSetStellarMsg;
    scpQuorumSetAmsg.v0().sequence = result->mSendMacSeq;
    scpQuorumSetAmsg.v0().mac =
            hmacSha256(result->mSendMacKey, xdr::xdr_to_opaque(result->mSendMacSeq, scpQuorumSetAmsg));
    ++result->mSendMacSeq;

    xdr::msg_ptr scpXdrBytes(xdr::xdr_to_msg(scpQuorumSetAmsg));
    size_t scpRequest_length = scpXdrBytes->raw_size();
    //following blocks until the full request has been written to socket
    size_t scpBytesWriiten = asio::write(basicAsioTcpSocket, asio::buffer(scpXdrBytes->raw_data(), scpRequest_length));

    //== now read response on connected socket
    std::vector<uint8_t> scpRespHttpHdr; //we just want 4 bytes which represents the http response hdr
    scpRespHttpHdr.resize(HDRSZ);

    try {

        asio::error_code ec_scp;
        //blocks until we get enough respinse data is read or error occurs.  
        //*Note: unlike read(), this behavior will not throw error if the data does not
        //meet the buffer size.
        size_t bytesRead = basicAsioTcpSocket.read_some(asio::buffer(scpRespHttpHdr), ec_scp); 
        if (ec_scp == asio::error::eof) {
            throw std::runtime_error("unexpected behavior.  Expecting peer to send scp quorum set response instead it close the connection");
        } else if (ec_scp) {
            throw std::runtime_error(fmt::format("asio error msg while reading the response header: {}", ec_scp.message()) );
        }
        if (bytesRead != HDRSZ) {
            throw std::runtime_error(fmt::format("Not able to read enough bytes for scp quorum set Http Response Header, num of bytes read: {}", bytesRead) );
        }  

        //== derive response body len from the response header
        size_t scpRepBodyLen = static_cast<size_t>(scpRespHttpHdr[0]);  
        scpRepBodyLen &= 0x7f; // clear the XDR 'continuation' bit
        scpRepBodyLen <<= 8;
        scpRepBodyLen |= scpRespHttpHdr[1]; //processing 2nd bit
        scpRepBodyLen <<= 8;    
        scpRepBodyLen |= scpRespHttpHdr[2]; //processing 3rd bit
        scpRepBodyLen <<= 8;
        scpRepBodyLen |= scpRespHttpHdr[3];  //processing 4th bit   
        if (scpRepBodyLen <= 0 || scpRepBodyLen > MAX_MESSAGE_SIZE) {
            result->drop("drop remote peer as scp quoprum set response is not valid", Peer::DropDirection::WE_DROPPED_REMOTE,
                Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch -- scp quorum set response from remote peer does not seem valid" \
                        " (note: dropped remote peer)." \
                        "  size of body length {}", scpRepBodyLen) );
        }
        CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - the response body for scp quorum set request length is: " << httpRespBodyLen;        

        std::vector<uint8_t> scpXdrBody;
        scpXdrBody.resize(scpRepBodyLen);
        try {

            asio::error_code ec_scpbody;
            size_t lenBytesReadForScpBody = basicAsioTcpSocket.read_some(asio::buffer(scpXdrBody), ec_scpbody);                        
            if (ec_scpbody == asio::error::eof) {
                throw std::runtime_error("Peer closed connection while reading the scp quorum set response body.");
            } else if (ec_scpbody) {
                throw std::runtime_error(fmt::format("asio error msg while reading the scp quorum set response body: {}", ec_scpbody.message()) );
            }

            if (lenBytesReadForScpBody != scpRepBodyLen) {
                throw std::runtime_error(fmt::format("Not able to read enough bytes the scp quorum set response body, num of bytes read: {}", lenBytesReadForScpBody) );
            }    

            xdr::xdr_get g(scpXdrBody.data(), scpXdrBody.data() + scpXdrBody.size());
            AuthenticatedMessage scpAM; 
            xdr::xdr_argpack_archive(g, scpAM);  
            stellar::StellarMessage sm = scpAM.v0().message; 
            stellar::MessageType msgType = sm.type();
            CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - received response from peer, messge type:" << msgType;
            switch(msgType)
            {
                case MessageType::GET_SCP_STATE: {
                    CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - remote peer ledger sequence #: "
                                << sm.getSCPLedgerSeq();                            
                    break;                    
                }   
                case MessageType::ERROR_MSG: {
                    stellar::Error & error = sm.error();
                    stellar::ErrorCode ec = error.code;
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - received err msg type for our scp quorum set request, error coe {}, error msg {}"
                        , ec, std::string{error.msg}) );    
                }
                default:
                    throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - scp quorum set msg of our sequence, received unexpected msg type {}", msgType) );                             
            }    

        } catch (xdr::xdr_runtime_error& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "received corrupt XDR", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling scp quorum set response, error: {}", e.what()) );
        } catch (std::exception& e) {
            //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
            throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling scp quorum set response, error: {}", e.what()) );
        }        

    } catch (std::exception& e) {
        //TODO: need to send this synchronously, default is async result->sendErrorAndDrop(ERR_DATA, "crypto error", Peer::DropMode::IGNORE_WRITE_QUEUE);
        throw std::runtime_error(fmt::format("TCPPeer::initiateSynch - exception unmarshalling scp quorum set response, error: {}", e.what()) );
    }

    CLOG(INFO, "Overlay") << "TCPPeer::initiateSynch - end.";
    return result;

}

TCPPeer::pointer
TCPPeer::initiate(Application& app, PeerBareAddress const& address)
{
    assert(address.getType() == PeerBareAddress::Type::IPv4);

    CLOG(DEBUG, "Overlay") << "TCPPeer:initiate"
                           << " to " << address.toString();
    assertThreadIsMain();
    auto socket = make_shared<SocketType>(app.getClock().getIOContext(), BUFSZ);
    auto result = make_shared<TCPPeer>(app, WE_CALLED_REMOTE, socket);
    result->mAddress = address;
    result->startIdleTimer();
    asio::ip::tcp::endpoint endpoint(
        asio::ip::address::from_string(address.getIP()), address.getPort());
    socket->next_layer().async_connect(
        endpoint, [result](asio::error_code const& error) {
            asio::error_code ec;
            if (!error)
            {
                asio::ip::tcp::no_delay nodelay(true);
                result->mSocket->next_layer().set_option(nodelay, ec);
            }
            else
            {
                ec = error;
            }

            result->connectHandler(ec);
        });
    return result;
}

TCPPeer::pointer
TCPPeer::accept(Application& app, shared_ptr<TCPPeer::SocketType> socket)
{
    assertThreadIsMain();
    shared_ptr<TCPPeer> result;
    asio::error_code ec;

    asio::ip::tcp::no_delay nodelay(true);
    socket->next_layer().set_option(nodelay, ec);

    if (!ec)
    {
        CLOG(DEBUG, "Overlay") << "TCPPeer:accept"
                               << "@" << app.getConfig().PEER_PORT;
        result = make_shared<TCPPeer>(app, REMOTE_CALLED_US, socket);
        result->startIdleTimer();
        result->startRead();
    }
    else
    {
        CLOG(DEBUG, "Overlay")
            << "TCPPeer:accept"
            << "@" << app.getConfig().PEER_PORT << " error " << ec.message();
    }

    return result;
}

TCPPeer::~TCPPeer()
{
    assertThreadIsMain();
    mIdleTimer.cancel();
    if (mSocket)
    {
        // Ignore: this indicates an attempt to cancel events
        // on a not-established socket.
        asio::error_code ec;

#ifndef _WIN32
        // This always fails on windows and ASIO won't
        // even build it.
        mSocket->next_layer().cancel(ec);
#endif
        mSocket->close(ec);
    }
}

std::string
TCPPeer::getIP() const
{
    std::string result;

    asio::error_code ec;
    auto ep = mSocket->next_layer().remote_endpoint(ec);
    if (!ec)
    {
        result = ep.address().to_string();
    }

    return result;
}

void
TCPPeer::sendMessage(xdr::msg_ptr&& xdrBytes)
{
    if (mState == CLOSING)
    {
        CLOG(ERROR, "Overlay")
            << "Trying to send message to " << toString() << " after drop";
        CLOG(ERROR, "Overlay") << REPORT_INTERNAL_BUG;
        return;
    }

    assertThreadIsMain();

    TimestampedMessage msg;
    msg.mEnqueuedTime = mApp.getClock().now();
    msg.mMessage = std::move(xdrBytes);
    mWriteQueue.emplace_back(std::move(msg));

    if (!mWriting)
    {
        mWriting = true;
        messageSender();
    }
}

void
TCPPeer::shutdown()
{
    if (mShutdownScheduled)
    {
        // should not happen, leave here for debugging purposes
        CLOG(ERROR, "Overlay") << "Double schedule of shutdown " << toString();
        CLOG(ERROR, "Overlay") << REPORT_INTERNAL_BUG;
        return;
    }

    mIdleTimer.cancel();
    mShutdownScheduled = true;
    auto self = static_pointer_cast<TCPPeer>(shared_from_this());

    // To shutdown, we first queue up our desire to shutdown in the strand,
    // behind any pending read/write calls. We'll let them issue first.
    self->getApp().postOnMainThread(
        [self]() {
            // Gracefully shut down connection: this pushes a FIN packet into
            // TCP which, if we wanted to be really polite about, we would wait
            // for an ACK from by doing repeated reads until we get a 0-read.
            //
            // But since we _might_ be dropping a hostile or unresponsive
            // connection, we're going to just post a close() immediately after,
            // and hope the kernel does something useful as far as putting any
            // queued last-gasp ERROR_MSG packet on the wire.
            //
            // All of this is voluntary. We can also just close(2) here and be
            // done with it, but we want to give some chance of telling peers
            // why we're disconnecting them.
            asio::error_code ec;
            self->mSocket->next_layer().shutdown(
                asio::ip::tcp::socket::shutdown_both, ec);
            if (ec)
            {
                CLOG(DEBUG, "Overlay")
                    << "TCPPeer::drop shutdown socket failed: " << ec.message();
            }
            self->getApp().postOnMainThread(
                [self]() {
                    // Close fd associated with socket. Socket is already shut
                    // down, but depending on platform (and apparently whether
                    // there was unread data when we issued shutdown()) this
                    // call might push RST onto the wire, or some other action;
                    // in any case it has to be done to free the OS resources.
                    //
                    // It will also, at this point, cancel any pending asio
                    // read/write handlers, i.e. fire them with an error code
                    // indicating cancellation.
                    asio::error_code ec2;
                    self->mSocket->close(ec2);
                    if (ec2)
                    {
                        CLOG(DEBUG, "Overlay")
                            << "TCPPeer::drop close socket failed: "
                            << ec2.message();
                    }
                },
                "TCPPeer: close");
        },
        "TCPPeer: shutdown");
}

void
TCPPeer::messageSender()
{
    assertThreadIsMain();

    // if nothing to do, mark progress and return.
    if (mWriteQueue.empty())
    {
        mWriting = false;
        // there is nothing to send and delayed shutdown was
        // requested - time to perform it
        if (mDelayedShutdown)
        {
            shutdown();
        }
        return;
    }

    // Take a snapshot of the contents of mWriteQueue into mWriteBuffers, in
    // terms of asio::const_buffers pointing into the elements of mWriteQueue,
    // and then issue a single multi-buffer ("scatter-gather") async_write that
    // covers the whole snapshot. We'll get called back when the batch is
    // completed, at which point we'll clear mWriteBuffers and remove the entire
    // snapshot worth of corresponding messages from mWriteQueue (though it may
    // have grown a bit in the meantime -- we remove only a prefix).
    assert(mWriteBuffers.empty());
    auto now = mApp.getClock().now();
    size_t expected_length = 0;
    size_t maxQueueSize = mApp.getConfig().MAX_BATCH_WRITE_COUNT;
    assert(maxQueueSize > 0);
    size_t const maxTotalBytes = mApp.getConfig().MAX_BATCH_WRITE_BYTES;
    for (auto& tsm : mWriteQueue)
    {
        tsm.mIssuedTime = now;
        size_t sz = tsm.mMessage->raw_size();
        mWriteBuffers.emplace_back(tsm.mMessage->raw_data(), sz);
        expected_length += sz;
        mEnqueueTimeOfLastWrite = tsm.mEnqueuedTime;
        // check if we reached any limit
        if (expected_length >= maxTotalBytes)
            break;
        if (--maxQueueSize == 0)
            break;
    }

    if (Logging::logDebug("Overlay"))
    {
        CLOG(DEBUG, "Overlay") << fmt::format(
            "messageSender {} - b:{} n:{}/{}", toString(), expected_length,
            mWriteBuffers.size(), mWriteQueue.size());
    }
    getOverlayMetrics().mAsyncWrite.Mark();
    auto self = static_pointer_cast<TCPPeer>(shared_from_this());
    asio::async_write(*(mSocket.get()), mWriteBuffers,
                      [self, expected_length](asio::error_code const& ec,
                                              std::size_t length) {
                          if (expected_length != length)
                          {
                              self->drop("error during async_write",
                                         Peer::DropDirection::WE_DROPPED_REMOTE,
                                         Peer::DropMode::IGNORE_WRITE_QUEUE);
                              return;
                          }
                          self->writeHandler(ec, length,
                                             self->mWriteBuffers.size());

                          // Walk through a _prefix_ of the write queue
                          // _corresponding_ to the write buffers we just sent.
                          // While walking, record the sent-time in metrics, but
                          // also advance iterator 'i' so we wind up with an
                          // iterator range to erase from the front of the write
                          // queue.
                          auto now = self->mApp.getClock().now();
                          auto i = self->mWriteQueue.begin();
                          while (!self->mWriteBuffers.empty())
                          {
                              i->mCompletedTime = now;
                              i->recordWriteTiming(self->getOverlayMetrics());
                              ++i;
                              self->mWriteBuffers.pop_back();
                          }

                          // Erase the messages from the write queue that we
                          // just forgot about the buffers for.
                          self->mWriteQueue.erase(self->mWriteQueue.begin(), i);

                          // continue processing the queue
                          if (!ec)
                          {
                              self->messageSender();
                          }
                      });
}

void
TCPPeer::TimestampedMessage::recordWriteTiming(OverlayMetrics& metrics)
{
    auto qdelay = std::chrono::duration_cast<std::chrono::nanoseconds>(
        mIssuedTime - mEnqueuedTime);
    auto wdelay = std::chrono::duration_cast<std::chrono::nanoseconds>(
        mCompletedTime - mIssuedTime);
    metrics.mMessageDelayInWriteQueueTimer.Update(qdelay);
    metrics.mMessageDelayInAsyncWriteTimer.Update(wdelay);
}

void
TCPPeer::writeHandler(asio::error_code const& error,
                      std::size_t bytes_transferred,
                      size_t messages_transferred)
{
    assertThreadIsMain();
    mLastWrite = mApp.getClock().now();

    if (error)
    {
        if (isConnected())
        {
            // Only emit a warning if we have an error while connected;
            // errors during shutdown or connection are common/expected.
            getOverlayMetrics().mErrorWrite.Mark();
            CLOG(ERROR, "Overlay")
                << "Error during sending message to " << toString();
        }
        if (mDelayedShutdown)
        {
            // delayed shutdown was requested - time to perform it
            shutdown();
        }
        else
        {
            // no delayed shutdown - we can drop normally
            drop("error during write", Peer::DropDirection::WE_DROPPED_REMOTE,
                 Peer::DropMode::IGNORE_WRITE_QUEUE);
        }
    }
    else if (bytes_transferred != 0)
    {
        LoadManager::PeerContext loadCtx(mApp, mPeerID);
        getOverlayMetrics().mMessageWrite.Mark(messages_transferred);
        getOverlayMetrics().mByteWrite.Mark(bytes_transferred);

        mPeerMetrics.mMessageWrite += messages_transferred;
        mPeerMetrics.mByteWrite += bytes_transferred;
    }
}

void
TCPPeer::noteErrorReadHeader(size_t nbytes, asio::error_code const& ec)
{
    receivedBytes(nbytes, false);
    getOverlayMetrics().mErrorRead.Mark();
    std::string msg("error reading message header: ");
    msg.append(ec.message());
    drop(msg, Peer::DropDirection::WE_DROPPED_REMOTE,
         Peer::DropMode::IGNORE_WRITE_QUEUE);
}

void
TCPPeer::noteShortReadHeader(size_t nbytes)
{
    receivedBytes(nbytes, false);
    getOverlayMetrics().mErrorRead.Mark();
    drop("short read of message header", Peer::DropDirection::WE_DROPPED_REMOTE,
         Peer::DropMode::IGNORE_WRITE_QUEUE);
}

void
TCPPeer::noteFullyReadHeader()
{
    receivedBytes(HDRSZ, false);
}

void
TCPPeer::noteErrorReadBody(size_t nbytes, asio::error_code const& ec)
{
    receivedBytes(nbytes, false);
    getOverlayMetrics().mErrorRead.Mark();
    std::string msg("error reading message body: ");
    msg.append(ec.message());
    drop(msg, Peer::DropDirection::WE_DROPPED_REMOTE,
         Peer::DropMode::IGNORE_WRITE_QUEUE);
}

void
TCPPeer::noteShortReadBody(size_t nbytes)
{
    receivedBytes(nbytes, false);
    getOverlayMetrics().mErrorRead.Mark();
    drop("short read of message body", Peer::DropDirection::WE_DROPPED_REMOTE,
         Peer::DropMode::IGNORE_WRITE_QUEUE);
}

void
TCPPeer::noteFullyReadBody(size_t nbytes)
{
    receivedBytes(nbytes, true);
}

void
TCPPeer::startRead()
{
    assertThreadIsMain();
    if (shouldAbort())
    {
        return;
    }

    mIncomingHeader.clear();

    CLOG(DEBUG, "Overlay") << "TCPPeer::startRead " << mSocket->in_avail()
                           << " from " << toString();

    mIncomingHeader.resize(HDRSZ);

    // We read large-ish (256KB) buffers of data from TCP which might have quite
    // a few messages in them. We want to digest as many of these
    // _synchronously_ as we can before we issue an async_read against ASIO.
    YieldTimer yt(mApp.getClock(), mApp.getConfig().MAX_BATCH_READ_PERIOD_MS,
                  mApp.getConfig().MAX_BATCH_READ_COUNT);
    while (mSocket->in_avail() >= HDRSZ && yt.shouldKeepGoing())
    {
        asio::error_code ec_hdr, ec_body;
        size_t n = mSocket->read_some(asio::buffer(mIncomingHeader), ec_hdr);
        if (ec_hdr)
        {
            noteErrorReadHeader(n, ec_hdr);
            return;
        }
        if (n != HDRSZ)
        {
            noteShortReadHeader(n);
            return;
        }
        size_t length = getIncomingMsgLength();
        if (mSocket->in_avail() >= length)
        {
            // We can finish reading a full message here synchronously,
            // which means we will count the received header bytes here.
            noteFullyReadHeader();
            if (length != 0)
            {
                mIncomingBody.resize(length);
                n = mSocket->read_some(asio::buffer(mIncomingBody), ec_body);
                if (ec_body)
                {
                    noteErrorReadBody(n, ec_body);
                    return;
                }
                if (n != length)
                {
                    noteShortReadBody(n);
                    return;
                }
                noteFullyReadBody(length);
                recvMessage();
            }
        }
        else
        {
            // We read a header synchronously, but don't have enough data in the
            // buffered_stream to read the body synchronously. Pretend we just
            // finished reading the header asynchronously, and punt to
            // readHeaderHandler to let it re-read the header and issue an async
            // read for the body.
            readHeaderHandler(asio::error_code(), HDRSZ);
            return;
        }
    }

    if (mSocket->in_avail() < HDRSZ)
    {
        // If there wasn't enough readable in the buffered stream to even get a
        // header (message length), issue an async_read and hope that the
        // buffering pulls in much more than just the 4 bytes we ask for here.
        getOverlayMetrics().mAsyncRead.Mark();
        auto self = static_pointer_cast<TCPPeer>(shared_from_this());
        asio::async_read(*(mSocket.get()), asio::buffer(mIncomingHeader),
                         [self](asio::error_code ec, std::size_t length) {
                             self->readHeaderHandler(ec, length);
                         });
    }
    else
    {
        // we have enough data but need to bounce on the main thread as we've
        // done too much work already
        auto self = static_pointer_cast<TCPPeer>(shared_from_this());
        self->getApp().postOnMainThread([self]() { self->startRead(); },
                                        "TCPPeer: startRead");
    }
}

size_t
TCPPeer::getIncomingMsgLength()
{
    size_t length = static_cast<size_t>(mIncomingHeader[0]);
    length &= 0x7f; // clear the XDR 'continuation' bit
    length <<= 8;
    length |= mIncomingHeader[1];
    length <<= 8;
    length |= mIncomingHeader[2];
    length <<= 8;
    length |= mIncomingHeader[3];
    if (length <= 0 ||
        (!isAuthenticated() && (length > MAX_UNAUTH_MESSAGE_SIZE)) ||
        length > MAX_MESSAGE_SIZE)
    {
        getOverlayMetrics().mErrorRead.Mark();
        CLOG(ERROR, "Overlay")
            << "TCP: message size unacceptable: " << length
            << (isAuthenticated() ? "" : " while not authenticated");
        drop("error during read", Peer::DropDirection::WE_DROPPED_REMOTE,
             Peer::DropMode::IGNORE_WRITE_QUEUE);
        length = 0;
    }
    return (length);
}

void
TCPPeer::connected()
{
    startRead();
}

void
TCPPeer::readHeaderHandler(asio::error_code const& error,
                           std::size_t bytes_transferred)
{
    assertThreadIsMain();

    if (error)
    {
        noteErrorReadHeader(bytes_transferred, error);
    }
    else if (bytes_transferred != HDRSZ)
    {
        noteShortReadHeader(bytes_transferred);
    }
    else
    {
        noteFullyReadHeader();
        size_t expected_length = getIncomingMsgLength();
        if (expected_length != 0)
        {
            mIncomingBody.resize(expected_length);
            auto self = static_pointer_cast<TCPPeer>(shared_from_this());
            asio::async_read(*mSocket.get(), asio::buffer(mIncomingBody),
                             [self, expected_length](asio::error_code ec,
                                                     std::size_t length) {
                                 self->readBodyHandler(ec, length,
                                                       expected_length);
                             });
        }
    }
}

void
TCPPeer::readBodyHandler(asio::error_code const& error,
                         std::size_t bytes_transferred,
                         std::size_t expected_length)
{
    assertThreadIsMain();

    if (error)
    {
        noteErrorReadBody(bytes_transferred, error);
    }
    else if (bytes_transferred != expected_length)
    {
        noteShortReadBody(bytes_transferred);
    }
    else
    {
        noteFullyReadBody(bytes_transferred);
        recvMessage();
        mIncomingHeader.clear();
        startRead();
    }
}

void
TCPPeer::recvMessage()
{
    assertThreadIsMain();
    try
    {
        xdr::xdr_get g(mIncomingBody.data(),
                       mIncomingBody.data() + mIncomingBody.size());
        AuthenticatedMessage am;
        xdr::xdr_argpack_archive(g, am);
        Peer::recvMessage(am);
    }
    catch (xdr::xdr_runtime_error& e)
    {
        CLOG(ERROR, "Overlay") << "recvMessage got a corrupt xdr: " << e.what();
        sendErrorAndDrop(ERR_DATA, "received corrupt XDR",
                         Peer::DropMode::IGNORE_WRITE_QUEUE);
    }
}

void
TCPPeer::drop(std::string const& reason, DropDirection dropDirection,
              DropMode dropMode)
{
    assertThreadIsMain();
    if (shouldAbort())
    {
        return;
    }

    if (mState != GOT_AUTH)
    {
        CLOG(DEBUG, "Overlay") << "TCPPeer::drop " << toString() << " in state "
                               << mState << " we called:" << mRole;
    }
    else if (dropDirection == Peer::DropDirection::WE_DROPPED_REMOTE)
    {
        CLOG(INFO, "Overlay")
            << "Dropping peer " << toString() << "; reason: " << reason;
    }
    else
    {
        CLOG(INFO, "Overlay")
            << "Peer " << toString() << " dropped us; reason: " << reason;
    }

    mState = CLOSING;

    auto self = static_pointer_cast<TCPPeer>(shared_from_this());
    getApp().getOverlayManager().removePeer(this);

    // if write queue is not empty, messageSender will take care of shutdown
    if ((dropMode == Peer::DropMode::IGNORE_WRITE_QUEUE) || !mWriting)
    {
        self->shutdown();
    }
    else
    {
        self->mDelayedShutdown = true;
    }
}
}

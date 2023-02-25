FROM ubuntu:20.04
LABEL Description="Stellar-core Build environment"

ENV HOME /root

SHELL ["/bin/bash", "-c"]

RUN echo  "=== Install dependencies and checkout source code ==="

# install ssh commands such as ssh-keyscan and git
RUN  apt-get -yq update
RUN apt-get -yqq install ssh
RUN  printf "2" |  apt-get -yqq install git

# add host github to ssh known_hosts file and get its the public key
RUN mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh && \
    /usr/bin/ssh-keyscan github.com > /root/.ssh/known_hosts
ARG SSH_PRV_KEY
RUN echo "${SSH_PRV_KEY}" > /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

RUN apt-get update

# C++ toolchain.  A toolchain is a set of tools (such as compiler, linker, and assembler) intended to build your project.
RUN printf "Y" | apt-get install software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update 

# common packages including prerequisites for clang.
#   Note:  build-essential installs g++ for Ubuntu.
RUN printf "Y" | apt-get install git build-essential pkg-config autoconf dh-autoreconf automake libtool bison flex libpq-dev libunwind-dev parallel

# Clang-format-5.0 - tool used to automatically format c++ code so that other developers don’t need to worry about style issues.  
# It’s used to format your c++ code before creating a pull request.
RUN printf "Y" | apt-get install clang-format

# clang++ needs to be install after "build-essential"; otherwise, build-essential overlays clang package
RUN printf "Y" | apt-get install clang

WORKDIR /usr/stellar-core
ARG LIB_VERSION
# clone repo into WORKDIR
RUN git clone --depth 1 -b ${LIB_VERSION} git@github.com:tbcasoft/stellar-core.git .
RUN echo -e  "curr dir: $(pwd), elements is working dir:\n$(ls)"

RUN echo "Setup env variable to use clang instead of g++"
RUN export CFLAGS="-O3 -g1 -fno-omit-frame-pointer"

RUN echo "=== About to run  autogen.sh ==="
RUN ./autogen.sh &> autogen.out
RUN ./configure &> configure.out
RUN echo "=== About to run  make, output stored in make.output file ==="
#RUN make clean
RUN make &> make.output

RUN echo "=== stellar-core built, now to compress the executable using UPX ==="
RUN wget https://github.com/upx/upx/releases/download/v4.0.1/upx-4.0.1-amd64_linux.tar.xz
RUN tar xvf upx-4.0.1-amd64_linux.tar.xz
RUN ./upx-4.0.1-amd64_linux/upx src/stellar-core
RUN echo "Looking for stellar-core binary in curr dir: $(pwd): $(find . -name "stellar-core" -print)"

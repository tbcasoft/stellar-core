// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "historywork/WriteSnapshotWork.h"
#include "database/Database.h"
#include "history/StateSnapshot.h"
#include "historywork/Progress.h"
#include "main/Application.h"
#include "util/XDRStream.h"
#include <Tracy.hpp>

namespace stellar
{

// Note, WriteSnapshotWork does not have any special retry clean-up logic:
// history items are written via XDROutputFileStream, which automatically
// truncates any existing files.
WriteSnapshotWork::WriteSnapshotWork(Application& app,
                                     std::shared_ptr<StateSnapshot> snapshot)
    : BasicWork(app, "write-snapshot", BasicWork::RETRY_A_LOT)
    , mSnapshot(snapshot)
{
}

BasicWork::State
WriteSnapshotWork::onRun()
{
    if (mDone)
    {
        /*
        When failure state is returned, depending on the Work's retry strategy, either a retry will
        be scheduled or work will cease execution.
        */
       CLOG_INFO(History, "Is write snapshot task done? ({})", mDone);
        return mSuccess ? State::WORK_SUCCESS : State::WORK_FAILURE;
    }

    std::weak_ptr<WriteSnapshotWork> weak(
        std::static_pointer_cast<WriteSnapshotWork>(shared_from_this()));

    auto work = [weak]() { //callback function
        auto self = weak.lock();
        if (!self)
        {
	    CLOG_ERROR(History, "Witin callback function for executed work  Unexpected state, work is nil");
            return;
        }
        ZoneScoped;

        CLOG_INFO(History, "Witin callback function for executed work {}, its current state {}, its status {}, is it done? {}", self->getName()
            , self->getState(), self->getStatus(), self->isDone() );

        auto snap = self->mSnapshot;
        bool success = true;
        if (!snap->writeHistoryBlocks())
        {
            success = false;
	    CLOG_INFO(History, "Witin callback function for executed work:  It is NOT done.");
        }

        // Not ideal, but needed to prevent race conditions with
        // main thread, since BasicWork's state is not thread-safe. This is a
        // temporary workaround, as a cleaner solution is needed.
        //#####self->mApp.postOnMainThread(

        self->mApp.postOnBackgroundThread(
            [weak, success]() {
                auto self = weak.lock();
                if (self)
                {
                    self->mDone = true;
                    self->mSuccess = success;
                    self->wakeUp();
		    CLOG_INFO(History, "Witin callback function for executed work:  Setting it to Done and Success, will also now put it back to RUNNING state.");
                }
            },
	    "(name of work) WriteSnapshotWork: finish");
    };

    // Throw the work over to a worker thread if we can use DB pools,
    // otherwise run on main thread.
    // NB: we post in both cases as to share the logic
    if (mApp.getDatabase().canUsePool())
    {
        CLOG_INFO(History, "About - There is a available thread within the connection pool.  This work will run using bgstart (background thread0.");
        mApp.postOnBackgroundThread(work, "WriteSnapshotWork: bgstart");
    }
    else
    {
        CLOG_WARNING(History, "Stellar is using SQL Lite (in-memory mode) instead of Postgres, does not seem right.  Check your stellar-core.cfg.");
        mApp.postOnMainThread(work, "WriteSnapshotWork: start");
    }
    
    CLOG_INFO(History, "Put work in a waiting state.  Will stay there until it's done and within the callback function will transistion work to RUNNING state.");
    return State::WORK_WAITING;
}
}

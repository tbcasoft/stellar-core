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
#include "util/Logging.h"
#include "util/GlobalChecks.h"

namespace stellar
{

/*
WriteSnapshotWork represents a task.  This task will be process within a background thread.
*/

// Note, WriteSnapshotWork does not have any special retry clean-up logic:
// history items are written via XDROutputFileStream, which automatically
// truncates any existing files.
WriteSnapshotWork::WriteSnapshotWork(Application& app,
                                     std::shared_ptr<StateSnapshot> snapshot)
    : BasicWork(app, "write-snapshot", BasicWork::RETRY_A_LOT)
    , mSnapshot(snapshot)
{
}

/*
A task placed on a work scheduler (see HistoryManagerImpl::takeSnapshotAndPublish).  The work scheduler will start this task.
Purpose of this task is to publish any queued checkpoints.  It is "step 3 - About to publish any checkpoints queued in the database"
in closing a ledger block.
*/
BasicWork::State
WriteSnapshotWork::onRun()
{
    if (mDone)
    {
        /*
        When failure state is returned, depending on the Work's retry strategy, either a retry will
        be scheduled or work will cease execution.

        */
        CLOG_INFO(History, "Is main thread? {}:  Is write snapshot task done? ({})", threadIsMain(), mDone);
        return mSuccess ? State::WORK_SUCCESS : State::WORK_FAILURE;
    }

    /*
    - a means to access the "work" if it's still around but doesn't keep "work" around if no one else needs it.  Specifically, we will process the work.
    However, the work may be remove by others so this allows us to check for validaity of the work.
    */
    std::weak_ptr<WriteSnapshotWork> weak(
        std::static_pointer_cast<WriteSnapshotWork>(shared_from_this()));

    auto work = [weak]() { //work will be executed either in a bgthread or main thread, depending on where it was posted.

        auto self = weak.lock();  //does the work still exist?  if yes, we will process it.
        if (!self)
        {
            CLOG_ERROR(History, "Is main thread? {}:   Witin body of  work . Unexpected state, work is nil", threadIsMain());
            return;
        }
        ZoneScoped;

        CLOG_INFO(History, "Is main thread? {}:  Witin body of executed work {}, its current state {}, its status {}, is it done? {}", threadIsMain(), self->getName()
            , self->getState(), self->getStatus(), self->isDone() );

        auto snap = self->mSnapshot;
        bool success = true;
        CLOG_INFO(History, "Is main thread? {}:  Witin body of executed work {}, about to write history blocks.", threadIsMain()
            , self->getName());
        if (!snap->writeHistoryBlocks())
        {
            success = false;
            CLOG_INFO(History, "Is main thread? {}:  Witin body of executed work:  Writing history blocks is NOT done.", threadIsMain());
        }

        CLOG_INFO(History, "Is main thread? {}:   Witin body of executed work {}:  about to set it to Done and Success, will also now put it back to RUNNING state."
            , threadIsMain(), self->getName());
        self->mDone = true;
        self->mSuccess = success;
        self->wakeUp();
        CLOG_INFO(History, "Is main thread? {}:  Witin body of executed work {}, completed changing state of work..", threadIsMain(), self->getName());  
    };

    // Throw the work over to a worker thread if we can use DB pools,
    // otherwise run on main thread.
    // NB: we post in both cases as to share the logic
    if (mApp.getDatabase().canUsePool())
    {
        CLOG_DEBUG(History, "Is main thread? {}:  About - There is a available thread within the connection pool.  Posting task to bgthread."
            , threadIsMain());
        mApp.postOnBackgroundThread(work, "WriteSnapshotWork: bgstart");
    }
    else
    {
        CLOG_WARNING(History, "Is main thread? {}:  Stellar is using SQL Lite (in-memory mode) instead of Postgres, does not seem right.  Check your stellar-core.cfg."
            , threadIsMain());
        mApp.postOnMainThread(work, "WriteSnapshotWork: main thread start");
    }

    CLOG_DEBUG(History, "Put work in a waiting state.  When work is executed, it will put back to RUNNING state.");
    return State::WORK_WAITING;
}
}

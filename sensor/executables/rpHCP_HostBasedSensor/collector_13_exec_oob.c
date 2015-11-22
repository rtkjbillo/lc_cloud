/*
Copyright 2015 refractionPOINT

Licensed under the Apache License, Version 2.0 ( the "License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define RPAL_FILE_ID                            96

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#ifdef RPAL_PLATFORM_DEBUG
#define _DEFAULT_TIME_DELTA     (60 * 30)
#else
#define _DEFAULT_TIME_DELTA     (0)
#endif

static
RBOOL
    isMemInModule
    (
        RU64 memBase,
        rList modules
    )
{
    RBOOL isInMod = FALSE;
    rSequence mod = NULL;

    RU64 modBase = 0;
    RU64 modSize = 0;

    if( NULL != modules )
    {
        rList_resetIterator( modules );

        while( rList_getSEQUENCE( modules, RP_TAGS_DLL, &mod ) )
        {
            if( rSequence_getPOINTER64( mod, RP_TAGS_BASE_ADDRESS, &modBase ) &&
                rSequence_getRU64( mod, RP_TAGS_MEMORY_SIZE, &modSize ) )
            {
                if( IS_WITHIN_BOUNDS( NUMBER_TO_PTR( memBase ), 4, NUMBER_TO_PTR( modBase ), modSize ) )
                {
                    isInMod = TRUE;
                    break;
                }
            }
        }

        rList_resetIterator( modules );
    }

    return isInMod;
}


static
RPVOID
    lookForExecOobIn
    (
        rEvent isTimeToStop,
        RU32 processId,
        rSequence originalRequest
    )
{
    rList mods = NULL;
    rList threads = NULL;
    RU32 threadId = 0;
    rList stackTrace = NULL;
    rSequence frame = NULL;
    RU64 pc = 0;
    RBOOL isFound = FALSE;
    rList traces = NULL;
    rSequence notif = NULL;
    rSequence taggedTrace = NULL;
    RU32 curThreadId = 0;
    RU32 curProcId = 0;

    curProcId = processLib_getCurrentPid();
    curThreadId = processLib_getCurrentThreadId();

    rpal_debug_info( "looking for execution out of bounds in process %d.", processId );

    if( NULL != ( traces = rList_new( RP_TAGS_STACK_TRACE, RPCM_SEQUENCE ) ) )
    {
        if( NULL != ( mods = processLib_getProcessModules( processId ) ) )
        {
            if( NULL != ( threads = processLib_getThreads( processId ) ) )
            {
                while( !rEvent_wait( isTimeToStop, 0 ) &&
                       rList_getRU32( threads, RP_TAGS_THREAD_ID, &threadId ) )
                {
                    if( curProcId == processId &&
                        curThreadId == threadId )
                    {
                        continue;
                    }

                    if( NULL != ( stackTrace = processLib_getStackTrace( processId, threadId ) ) )
                    {
                        while( !rEvent_wait( isTimeToStop, 0 ) &&
                            rList_getSEQUENCE( stackTrace, RP_TAGS_STACK_TRACE_FRAME, &frame ) )
                        {
                            if( rSequence_getRU64( frame, RP_TAGS_STACK_TRACE_FRAME_PC, &pc ) &&
                                0 != pc &&
                                !isMemInModule( pc, mods ) )
                            {
                                rpal_debug_info( "covert execution detected in pid %d at 0x%016llX.", 
                                                 processId, 
                                                 pc );
                                if( NULL != ( taggedTrace = rSequence_new() ) )
                                {
                                    if( rSequence_addRU32( taggedTrace, RP_TAGS_THREAD_ID, threadId ) &&
                                        rSequence_addLISTdup( taggedTrace, 
                                                              RP_TAGS_STACK_TRACE_FRAMES, 
                                                              stackTrace ) )
                                    {
                                        rList_addSEQUENCEdup( traces, taggedTrace );
                                        isFound = TRUE;
                                    }

                                    rSequence_free( taggedTrace );
                                }
                                break;
                            }
                        }

                        rList_free( stackTrace );
                    }
                }

                rList_free( threads );
            }

            rList_free( mods );
        }

        if( isFound &&
            NULL != ( notif = processLib_getProcessInfo( processId ) ) )
        {
            if( !rSequence_addLIST( notif, RP_TAGS_STACK_TRACES, traces ) )
            {
                rList_free( traces );
            }

            hbs_markAsRelated( originalRequest, notif );

            notifications_publish( RP_TAGS_NOTIFICATION_EXEC_OOB, notif );

            rSequence_free( notif );
        }
        else
        {
            rList_free( traces );
        }
    }

    return NULL;
}

static
RPVOID
    lookForExecOob
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;

    if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
    {
        proc = procs;

        while( 0 != proc->pid &&
            rpal_memory_isValid( isTimeToStop ) &&
            !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
        {
            lookForExecOobIn( isTimeToStop, proc->pid, originalRequest );
            proc++;
        }

        rpal_memory_free( procs );
    }

    return NULL;
}

static
RVOID
    scan_for_exec_oob
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RU32 pid = (RU32)( -1 );
    rEvent dummy = NULL;

    UNREFERENCED_PARAMETER( eventType );

    rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid );

    if( NULL != ( dummy = rEvent_create( TRUE ) ) )
    {
        if( (RU32)( -1 ) == pid )
        {
            lookForExecOob( dummy, event );
        }
        else
        {
            lookForExecOobIn( dummy, pid, event );
        }

        rEvent_free( dummy );
    }
}

RBOOL
    collector_13_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU64 timeDelta = 0;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rpal_memory_isValid( config ) ||
            !rSequence_getTIMEDELTA( config, RP_TAGS_TIMEDELTA, &timeDelta ) )
        {
            timeDelta = _DEFAULT_TIME_DELTA;
        }

        if( notifications_subscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ,
                                     NULL,
                                     0,
                                     NULL,
                                     scan_for_exec_oob ) &&
            ( 0 == timeDelta ||
              rThreadPool_scheduleRecurring( hbsState->hThreadPool, timeDelta, lookForExecOob, NULL, TRUE ) ) )
        {
            isSuccess = TRUE;
        }
        else
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ, NULL, scan_for_exec_oob );
        }
    }

    return isSuccess;
}

RBOOL
collector_13_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_EXEC_OOB_REQ, NULL, scan_for_exec_oob );

        isSuccess = TRUE;
    }

    return isSuccess;
}

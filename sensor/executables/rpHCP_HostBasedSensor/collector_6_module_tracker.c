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

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <processLib/processLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <kernelAcquisitionLib/common.h>

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#include <TlHelp32.h>
#endif

#define RPAL_FILE_ID         66

#define MAX_SNAPSHOT_SIZE 1536

typedef struct
{
    RU32 procId;
    RU64 baseAddr;
    RU64 size;
} _moduleHistEntry;

static RBOOL g_is_kernel_failure = FALSE;  // Kernel acquisition failed for this method

static
RS32
    _cmpModule
    (
        _moduleHistEntry* m1,
        _moduleHistEntry* m2
    )
{
    RS32 ret = 0;

    if( NULL != m1 &&
        NULL != m2 )
    {
        ret = (RS32)rpal_memory_memcmp( m1, m2, sizeof( *m1 ) );
    }

    return ret;
}

static
RPVOID
    userModeDiff
    (
        rEvent isTimeToStop
    )
{
    rBlob previousSnapshot = NULL;
    rBlob newSnapshot = NULL;
    _moduleHistEntry curModule = { 0 };
    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    rList modules = NULL;
    rSequence module = NULL;

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( NULL != ( processes = processLib_getProcessEntries( FALSE ) ) )
        {
            if( NULL != ( newSnapshot = rpal_blob_create( 1000 * sizeof( _moduleHistEntry ),
                                                          1000 * sizeof( _moduleHistEntry ) ) ) )
            {
                curProc = processes;
                while( rpal_memory_isValid( isTimeToStop ) &&
#ifdef RPAL_PLATFORM_WINDOWS
                       !rEvent_wait( isTimeToStop, 0 ) &&
#else
                       // Module listing outside of 
                       !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 1 ) ) &&
#endif
                       0 != curProc->pid )
                {
                    if( NULL != ( modules = processLib_getProcessModules( curProc->pid ) ) )
                    {
                        while( rpal_memory_isValid( isTimeToStop ) &&
                               !rEvent_wait( isTimeToStop, 20 ) &&
                               rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
                        {
                            if( rSequence_getPOINTER64( module,
                                                        RP_TAGS_BASE_ADDRESS, 
                                                        &( curModule.baseAddr ) ) &&
                                rSequence_getRU64( module, 
                                                   RP_TAGS_MEMORY_SIZE, 
                                                   &(curModule.size) ) )
                            {
                                curModule.procId = curProc->pid;
                                rpal_blob_add( newSnapshot, &curModule, sizeof( curModule ) );
                                if( NULL != previousSnapshot &&
                                    -1 == rpal_binsearch_array( rpal_blob_getBuffer( previousSnapshot ),
                                                                rpal_blob_getSize( previousSnapshot ) /
                                                                    sizeof( _moduleHistEntry ),
                                                                sizeof( _moduleHistEntry ),
                                                                &curModule, 
                                                                (rpal_ordering_func)_cmpModule ) )
                                {
                                    rSequence_addTIMESTAMP( module,
                                                            RP_TAGS_TIMESTAMP,
                                                            rpal_time_getGlobal() );
                                    notifications_publish( RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                                           module );
                                }
                            }
                        }

                        rList_free( modules );
                    }

                    curProc++;
                }

                if( !rpal_sort_array( rpal_blob_getBuffer( newSnapshot ),
                                      rpal_blob_getSize( newSnapshot ) / sizeof( _moduleHistEntry ),
                                      sizeof( _moduleHistEntry ),
                                      (rpal_ordering_func)_cmpModule ) )
                {
                    rpal_debug_warning( "error sorting modules" );
                }
            }

            rpal_memory_free( processes );
        }

        if( NULL != previousSnapshot )
        {
            rpal_blob_free( previousSnapshot );
        }
        previousSnapshot = newSnapshot;
        newSnapshot = NULL;
    }

    if( NULL != previousSnapshot )
    {
        rpal_blob_free( previousSnapshot );
    }

    return NULL;
}

static RBOOL
    notifyOfKernelModule
    (
        KernelAcqModule* module
    )
{
    RBOOL isSuccess = FALSE;
    rSequence notif = NULL;
    RU32 pathLength = 0;
    RU32 i = 0;
    RNATIVESTR dirSep = RPAL_FILE_LOCAL_DIR_SEP_N;

    if( NULL != module )
    {
        if( NULL != ( notif = rSequence_new() ) )
        {
            rSequence_addTIMESTAMP( notif, RP_TAGS_TIMESTAMP, module->ts );
            rSequence_addRU32( notif, RP_TAGS_PROCESS_ID, module->pid );
            rSequence_addPOINTER64( notif, RP_TAGS_BASE_ADDRESS, (RU64)module->baseAddress );
            rSequence_addRU64( notif, RP_TAGS_MEMORY_SIZE, module->imageSize );

            if( 0 != ( pathLength = rpal_string_strlenn( module->path ) ) )
            {
                rSequence_addSTRINGN( notif, RP_TAGS_FILE_PATH, module->path );

                // For compatibility with user mode we extract the module name.
                for( i = pathLength - 1; i != 0; i-- )
                {
                    if( dirSep[ 0 ] == module->path[ i ] )
                    {
                        i++;
                        break;
                    }
                }

                rSequence_addSTRINGN( notif, RP_TAGS_MODULE_NAME, &( module->path[ i ] ) );

                isSuccess = TRUE;
            }

            rSequence_free( notif );
        }
    }

    return isSuccess;
}

static RVOID
    kernelModeDiff
    (
        rEvent isTimeToStop
    )
{
    RU32 i = 0;
    RU32 nScratch = 0;
    KernelAcqModule new_from_kernel[ 200 ] = { 0 };

    while( !rEvent_wait( isTimeToStop, 1000 ) )
    {
        nScratch = ARRAY_N_ELEM( new_from_kernel );
        rpal_memory_zero( new_from_kernel, sizeof( new_from_kernel ) );
        if( !kAcq_getNewModules( new_from_kernel, &nScratch ) )
        {
            rpal_debug_warning( "kernel acquisition for new modules failed" );
            g_is_kernel_failure = TRUE;
            break;
        }

        for( i = 0; i < nScratch; i++ )
        {
            notifyOfKernelModule( &(new_from_kernel[ i ]) );
        }
    }
}


static RPVOID
    moduleDiffThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( kAcq_isAvailable() &&
            !g_is_kernel_failure )
        {
            // We first attempt to get new modules through
            // the kernel mode acquisition driver
            rpal_debug_info( "running kernel acquisition module notification" );
            kernelModeDiff( isTimeToStop );
        }
        // If the kernel mode fails, or is not available, try
        // to revert to user mode
        else if( !rEvent_wait( isTimeToStop, 0 ) )
        {
            rpal_debug_info( "running usermode acquisition module notification" );
            userModeDiff( isTimeToStop );
        }
    }

    return NULL;
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_6_events[] = { RP_TAGS_NOTIFICATION_MODULE_LOAD,
                                  0 };

RBOOL
    collector_6_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rThreadPool_task( hbsState->hThreadPool, moduleDiffThread, NULL ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_6_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

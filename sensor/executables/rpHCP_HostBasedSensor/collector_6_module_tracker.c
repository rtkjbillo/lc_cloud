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

#ifdef RPAL_PLATFORM_WINDOWS
#include <windows_undocumented.h>
#include <TlHelp32.h>
#endif

#define RPAL_FILE_ID         66


typedef struct
{
    RU32 procId;
    RU64 baseAddr;
    RU64 size;
} _moduleHistEntry;

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
    diffProcessModules
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rBlob previousSnapshot = NULL;
    rBlob newSnapshot = NULL;
    _moduleHistEntry curModule = { 0 };
    processLibProcEntry* processes = NULL;
    processLibProcEntry* curProc = NULL;
    rList modules = NULL;
    rSequence module = NULL;

    UNREFERENCED_PARAMETER( ctx );

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
                       !rEvent_wait( isTimeToStop, 0 ) &&
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
        if( rThreadPool_task( hbsState->hThreadPool, diffProcessModules, NULL ) )
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

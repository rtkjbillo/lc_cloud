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
#include <rpHostCommonPlatformLib/rTags.h>
#include "stateful_framework.h"
#include "stateful_events.h"

#define RPAL_FILE_ID       106

static rQueue g_events = NULL;
static rVector g_liveMachines = NULL;

static StatefulMachineDescriptor* g_statefulMachines[] =
{
    // Need to set various platform recon categories
    ENABLED_STATEFUL( 0 ),
    // Need more timely module notifications on other platforms for this to be relevant
    ENABLED_WINDOWS_STATEFUL( 1 ),
    // Need to categorize document software on other platforms
    ENABLED_WINDOWS_STATEFUL( 2 )
};

static
RVOID
    _freeSmEvent
    (
        StatefulEvent* evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rRefCount_release( evt->ref, NULL );
}

static RPVOID
    updateThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    StatefulMachine* tmpMachine = NULL;
    StatefulEvent* event = NULL;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( g_events, (RPVOID*)&event, NULL, MSEC_FROM_SEC( 1 ) ) )
        {
            // First we update currently running machines
            for( i = 0; i < g_liveMachines->nElements; i++ )
            {
                //rpal_debug_info( "SM begin update ( %p / %p )", g_liveMachines->elements[ i ], ((StatefulMachine*)g_liveMachines->elements[ i ])->desc );

                if( !SMUpdate( g_liveMachines->elements[ i ], event ) )
                {
                    //rpal_debug_info( "SM no longer required ( %p / %p )", g_liveMachines->elements[ i ], ((StatefulMachine*)g_liveMachines->elements[ i ])->desc );

                    // Machine indicated it is no longer live
                    SMFreeMachine( g_liveMachines->elements[ i ] );
                    if( rpal_vector_remove( g_liveMachines, i ) )
                    {
                        i--;
                    }
                }
            }

            // Then we prime any new machines
            for( i = 0; i < ARRAY_N_ELEM( g_statefulMachines ); i++ )
            {
                if( NULL != ( tmpMachine = SMPrime( g_statefulMachines[ i ], event ) ) )
                {
                    //rpal_debug_info( "SM created ( %p / %p )", tmpMachine, g_statefulMachines[ i ] );

                    // New machines get added to the pool of live machines
                    if( !rpal_vector_add( g_liveMachines, tmpMachine ) )
                    {
                        SMFreeMachine( tmpMachine );
                    }
                }
            }

            _freeSmEvent( event, 0 );
        }
    }

    return NULL;
}

static RVOID
    addNewSmEvent
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    StatefulEvent* statefulEvent = NULL;

    if( NULL != event )
    {
        if( NULL != ( statefulEvent = SMEvent_new( notifType, event ) ) )
        {
            if( !rQueue_add( g_events, statefulEvent, sizeof( statefulEvent ) ) )
            {
                _freeSmEvent( statefulEvent, 0 );
            }
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_20_events[] = { STATEFUL_MACHINE_0_EVENT,
                                   STATEFUL_MACHINE_1_EVENT,
                                   0 };

RBOOL
    collector_20_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
    RU32 j = 0;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rQueue_create( &g_events, (queue_free_func)_freeSmEvent, 200 ) )
        {
            if( NULL != ( g_liveMachines = rpal_vector_new() ) )
            {
                if( rThreadPool_task( hbsState->hThreadPool, updateThread, NULL ) )
                {
                    isSuccess = TRUE;
                }
            }
        }

        if( isSuccess )
        {
            for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
            {
                j = 0;

                while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
                {
                    if( !notifications_subscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                  NULL, 
                                                  0, 
                                                  NULL, 
                                                  addNewSmEvent ) )
                    {
                        isSuccess = FALSE;
                        break;
                    }

                    j++;
                }
            }
        }

        if( !isSuccess )
        {
            for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
            {
                j = 0;

                while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
                {
                    if( !notifications_unsubscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                    NULL,
                                                    addNewSmEvent ) )
                    {
                        isSuccess = FALSE;
                    }

                    j++;
                }
            }
            rQueue_free( g_events );
            g_events = NULL;
            rpal_vector_free( g_liveMachines );
            g_liveMachines = NULL;
        }
    }

    return isSuccess;
}

RBOOL
    collector_20_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
    RU32 j = 0;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        for( i = 0; i < ARRAY_N_ELEM( hbsState->collectors ); i++ )
        {
            j = 0;

            while( 0 != hbsState->collectors[ i ].externalEvents[ j ] )
            {
                if( !notifications_unsubscribe( hbsState->collectors[ i ].externalEvents[ j ],
                                                NULL,
                                                addNewSmEvent ) )
                {
                    isSuccess = FALSE;
                }

                j++;
            }
        }

        rQueue_free( g_events );
        g_events = NULL;
        for( i = 0; i < g_liveMachines->nElements; i++ )
        {
            SMFreeMachine( g_liveMachines->elements[ i ] );
        }
        rpal_vector_free( g_liveMachines );
        g_liveMachines = NULL;
        isSuccess = TRUE;
    }

    return isSuccess;
}
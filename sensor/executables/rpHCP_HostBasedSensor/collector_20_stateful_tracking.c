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
#include "stateful_widgets.h"
#include "stateful_events.h"


#define RPAL_FILE_ID       106

static rQueue g_events = NULL;

static
RVOID
    _freeSamEvent
    (
        SAMEvent* evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rRefCount_release( evt->ref, NULL );
}

static
RVOID
    _freeEvt
    (
        rSequence evt,
        RU32 unused
    )
{
    UNREFERENCED_PARAMETER( unused );
    rSequence_free( evt );
}

static RVOID
    sendNotification
    (
        rpcm_tag eventType,
        SAMStateVector* stateVector
    )
{
    SAMState* state = NULL;
    SAMEvent* event = NULL;
    RU32 i = 0;
    RU32 j = 0;
    rList states = NULL;
    rSequence wrapper = NULL;
    rSequence notif = NULL;

    if( NULL != stateVector )
    {
        for( i = 0; i < stateVector->states->nElements; i++ )
        {
            state = stateVector->states->elements[ i ];
            if( NULL != ( notif = rSequence_new() ) )
            {
                if( NULL != ( states = rList_new( RP_TAGS_EVENT, RPCM_SEQUENCE ) ) )
                {
                    if( !rSequence_addLIST( notif, RP_TAGS_EVENTS, states ) )
                    {
                        rList_free( states );
                        states = NULL;
                        rSequence_free( notif );
                        notif = NULL;
                    }
                }
                else
                {
                    rSequence_free( notif );
                    notif = NULL;
                }
            }
                
            if( NULL != notif )
            {
                for( j = 0; j < state->events->nElements; j++ )
                {
                    event = state->events->elements[ j ];
                    if( NULL != ( wrapper = rSequence_new() ) )
                    {
                        if( !rSequence_addSEQUENCE( wrapper, event->eventType, rSequence_duplicate( event->event ) ) || 
                            !rList_addSEQUENCE( states, wrapper ) )
                        {
                            rSequence_free( wrapper );
                        }
                    }
                }

                notifications_publish( eventType, notif );

                rSequence_free( notif );
            }
        }
    }
}

static RPVOID
    updateSamThread
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    SAMStateVector* hits = NULL;
    SAMEvent* event = NULL;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( g_events, &event, NULL, MSEC_FROM_SEC( 1 ) ) )
        {
            for( i = 0; i < ARRAY_N_ELEM( stateful_events ); i++ )
            {
                if( NULL != ( hits = SAMUpdate( stateful_events[ i ].instance, event ) ) )
                {
                    sendNotification( stateful_events[ i ].output_event, hits );
                    SAMStateVector_free( hits );
                }
            }

            _freeSamEvent( event, 0 );
        }
    }

    return NULL;
}

static RVOID
    addNewSamEvent
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    SAMEvent* samEvent = NULL;

    if( NULL != event )
    {
        if( NULL != ( samEvent = SAMEvent_new( notifType, event ) ) )
        {
            if( !rQueue_add( g_events, samEvent, sizeof( samEvent ) ) )
            {
                _freeSamEvent( samEvent, 0 );
            }
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_20_events[] = { 0 };

RBOOL
    collector_20_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        for( i = 0; i < ARRAY_N_ELEM( stateful_events ); i++ )
        {
            if( stateful_events[ i ].isEnabled )
            {
                if( NULL == ( stateful_events[ i ].instance = stateful_events[ i ].create() ) )
                {
                    rpal_debug_error( "could not create stateful machine %d", i );
                }
            }
        }

        if( rQueue_create( &g_events, _freeSamEvent, 200 ) )
        {
            if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, addNewSamEvent ) )
            {
                if( rThreadPool_task( hbsState->hThreadPool, updateSamThread, NULL ) )
                {
                    isSuccess = TRUE;
                }
                else
                {
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, g_events, NULL );
                }
            }
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

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, addNewSamEvent ) )
        {
            if( rQueue_free( g_events ) )
            {
                for( i = 0; i < ARRAY_N_ELEM( stateful_events ); i++ )
                {
                    if( NULL != stateful_events[ i ].instance )
                    {
                        SAMFree( stateful_events[ i ].instance );
                        stateful_events[ i ].instance = NULL;
                    }
                }

                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}
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

#define RPAL_FILE_ID       94

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define _HISTORY_MAX_LENGTH     (1000)
#define _HISTORY_MAX_SIZE       (1024*1024*1)

typedef struct
{
    rpcm_tag* pElems;
    RU32 nElem;
    rMutex mutex;
} _EventList;


static HbsState* g_state = NULL;

static _EventList g_exfil_profile = { 0 };
static _EventList g_exfil_adhoc = { 0 };
static _EventList g_critical_profile = { 0 };
static _EventList g_critical_adhoc = { 0 };

static RU32 g_cur_size = 0;
static rSequence g_history[ _HISTORY_MAX_LENGTH ] = { 0 };
static RU32 g_history_head = 0;
static rMutex g_history_mutex = NULL;

static
RBOOL
    _initEventList
    (
        _EventList* pList
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( NULL != ( pList->mutex = rMutex_create() ) )
        {
            pList->pElems = NULL;
            pList->nElem = 0;
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

static
RBOOL
    _deinitEventList
    (
        _EventList* pList
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( rpal_memory_isValid( pList->mutex ) )
        {
            rMutex_free( pList->mutex );
            pList->mutex = NULL;
        }

        if( rpal_memory_isValid( pList->pElems ) )
        {
            rpal_memory_free( pList->pElems );
            pList->pElems = NULL;
        }

        pList->nElem = 0;
    }

    return isSuccess;
}

static
RBOOL
    _addEventId
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;
    RPVOID original = NULL;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            pList->nElem++;
            original = pList->pElems;
            pList->pElems = rpal_memory_reAlloc( pList->pElems, pList->nElem * sizeof( *( pList->pElems ) ) );
            if( rpal_memory_isValid( pList->pElems ) )
            {
                pList->pElems[ pList->nElem - 1 ] = eventId;
                isSuccess = TRUE;
            }
            else
            {
                pList->pElems = original;
                pList->nElem--;
            }

            rpal_sort_array( pList->pElems, 
                             pList->nElem, 
                             sizeof( *( pList->pElems ) ), 
                             (rpal_ordering_func)rpal_order_RU32 );

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

static
RBOOL
    _removeEventId
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;
    RU32 i = 0;
    RPVOID original = NULL;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            if( (RU32)( -1 ) != ( i = rpal_binsearch_array( pList->pElems, 
                                                            pList->nElem, 
                                                            sizeof( *( pList->pElems ) ), 
                                                            &eventId,
                                                            (rpal_ordering_func)rpal_order_RU32 ) ) )
            {
                rpal_memory_memmove( &( pList->pElems[ i ] ), 
                                     &( pList->pElems[ i + 1 ] ), 
                                     ( pList->nElem - i - 1 ) * sizeof( *( pList->pElems ) ) );
                pList->nElem--;
                original = pList->pElems;
                pList->pElems = rpal_memory_realloc( pList->pElems,
                                                     pList->nElem * sizeof( *( pList->pElems ) ) );
                if( rpal_memory_isValid( pList->pElems ) )
                {
                    rpal_sort_array( pList->pElems, 
                                     pList->nElem, 
                                     sizeof( *( pList->pElems ) ), 
                                     (rpal_ordering_func)rpal_order_RU32 );
                    isSuccess = TRUE;
                }
                else
                {
                    pList->nElem++;
                    pList->pElems = original;
                }
            }

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

static
RBOOL
    _isEventIn
    (
        _EventList* pList,
        rpcm_tag eventId
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pList )
    {
        if( rMutex_lock( pList->mutex ) )
        {
            if( (RU32)( -1 ) != rpal_binsearch_array( pList->pElems,
                                                      pList->nElem,
                                                      sizeof( *( pList->pElems ) ),
                                                      &eventId,
                                                      (rpal_ordering_func)rpal_order_RU32 ) )
            {
                isSuccess = TRUE;
            }

            rMutex_unlock( pList->mutex );
        }
    }

    return isSuccess;
}

static
RVOID
    recordEvent
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 i = 0;
    rSequence tmpNotif = NULL;
    rSequence wrapper = NULL;

    if( rpal_memory_isValid( notif ) )
    {
        if( rMutex_lock( g_history_mutex ) )
        {
            if( g_history_head >= ARRAY_N_ELEM( g_history ) )
            {
                g_history_head = 0;
            }

            if( NULL != g_history[ g_history_head ] )
            {
                g_cur_size -= rSequence_getEstimateSize( g_history[ g_history_head ] );

                rSequence_free( g_history[ g_history_head ] );
                g_history[ g_history_head ] = NULL;
            }

            if( NULL != ( tmpNotif = rSequence_duplicate( notif ) ) )
            {
                if( NULL != ( wrapper = rSequence_new() ) )
                {
                    if( rSequence_addSEQUENCE( wrapper, notifId, tmpNotif ) )
                    {
                        g_history[ g_history_head ] = wrapper;
                        g_cur_size += rSequence_getEstimateSize( wrapper );

                        i = g_history_head + 1;
                        while( _HISTORY_MAX_SIZE < g_cur_size )
                        {
                            if( i >= ARRAY_N_ELEM( g_history ) )
                            {
                                i = 0;
                            }

                            g_cur_size -= rSequence_getEstimateSize( g_history[ i ] );

                            rSequence_free( g_history[ i ] );
                            g_history[ i ] = NULL;
                            i++;
                        }

                        g_history_head++;
                    }
                    else
                    {
                        rSequence_free( wrapper );
                        rSequence_free( tmpNotif );
                    }
                }
                else
                {
                    rSequence_free( tmpNotif );
                }
            }

            rpal_debug_info( "History size: %d KB", ( g_cur_size / 1024 ) );

            rMutex_unlock( g_history_mutex );
        }
    }
}

static 
RVOID
    exfilFunc
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    rSequence wrapper = NULL;
    rSequence tmpNotif = NULL;
    RU64 tmpTime = 0;

    if( rpal_memory_isValid( notif ) &&
        NULL != g_state )
    {
        if( _isEventIn( &g_exfil_profile, notifId ) ||
            _isEventIn( &g_exfil_adhoc, notifId ) )
        {
            if( NULL != ( wrapper = rSequence_new() ) )
            {
                if( NULL != ( tmpNotif = rSequence_duplicate( notif ) ) )
                {
                    if( rSequence_addSEQUENCE( wrapper, notifId, tmpNotif ) )
                    {
                        if( !rQueue_add( g_state->outQueue, wrapper, 0 ) )
                        {
                            rSequence_free( wrapper );
                        }
                    }
                    else
                    {
                        rSequence_free( wrapper );
                        rSequence_free( tmpNotif );
                    }
                }
            }
        }
        else
        {
            recordEvent( notifId, notif );
        }

        if( _isEventIn( &g_critical_profile, notifId ) ||
            _isEventIn( &g_critical_adhoc, notifId ) )
        {
            if( rMutex_lock( g_state->mutex ) )
            {
                tmpTime = rpal_time_getGlobal() + 2;

                if( g_state->liveUntil < tmpTime )
                {
                    g_state->liveUntil = tmpTime;
                }

                rMutex_unlock( g_state->mutex );
            }
        }
    }
}

static
RVOID
    dumpHistory
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 i = 0;
    rSequence tmp = NULL;
    UNREFERENCED_PARAMETER( notifId );
    UNREFERENCED_PARAMETER( notif );

    if( rMutex_lock( g_history_mutex ) )
    {
        for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
        {
            if( rpal_memory_isValid( g_history[ i ] ) &&
                NULL != ( tmp = rSequence_duplicate( g_history[ i ] ) ) )
            {
                hbs_markAsRelated( notif, tmp );

                if( !rQueue_add( g_state->outQueue, tmp, 0 ) )
                {
                    rSequence_free( tmp );
                }
            }
        }

        rMutex_unlock( g_history_mutex );
    }
}

static
RPVOID
    stopExfilCb
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rpcm_tag* exfilStub = (rpcm_tag*)ctx;

    UNREFERENCED_PARAMETER( isTimeToStop );

    if( rpal_memory_isValid( exfilStub ) )
    {
        if( _removeEventId( &g_exfil_adhoc, *exfilStub ) )
        {
            rpal_debug_info( "removing adhoc exfil (expired): %d", *exfilStub );
        }

        rpal_memory_free( exfilStub );
    }

    return NULL;
}

static
RVOID
    add_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;
    RTIME expire = 0;
    rpcm_tag* exfilStub = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _addEventId( &g_exfil_adhoc, eventId ) )
            {
                rpal_debug_info( "adding adhoc exfil: %d", eventId );

                if( rSequence_getTIMESTAMP( event, RP_TAGS_EXPIRY, &expire ) )
                {
                    if( NULL != ( exfilStub = rpal_memory_alloc( sizeof( *exfilStub ) ) ) )
                    {
                        *exfilStub = eventId;
                        if( !rThreadPool_scheduleOneTime( g_state->hThreadPool, 
                                                          expire, 
                                                          stopExfilCb, 
                                                          exfilStub ) )
                        {
                            rpal_memory_free( exfilStub );
                        }
                        else
                        {
                            rpal_debug_info( "adding callback for expiry on new adhoc exfil" );
                        }
                    }
                }
            }
        }
    }
}


static
RVOID
    del_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _removeEventId( &g_exfil_adhoc, eventId ) )
            {
                rpal_debug_info( "removing adhoc exfil: %d", eventId );
            }
        }
    }
}


static
RVOID
    get_exfil
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList events = NULL;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rMutex_lock( g_exfil_adhoc.mutex ) )
        {
            if( NULL != ( events = rList_new( RP_TAGS_HBS_NOTIFICATION_ID, RPCM_RU32 ) ) )
            {
                if( rpal_memory_isValid( g_exfil_adhoc.pElems ) )
                {
                    for( i = 0; i < g_exfil_adhoc.nElem; i++ )
                    {
                        rList_addRU32( events, g_exfil_adhoc.pElems[ i ] );
                    }
                }

                if( !rSequence_addLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, events ) )
                {
                    rList_free( events );
                    events = NULL;
                }

                notifications_publish( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP, event );
            }

            rMutex_unlock( g_exfil_adhoc.mutex );
        }
    }
}

static
RPVOID
    stopCriticalCb
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rpcm_tag* criticalStub = (rpcm_tag*)ctx;

    UNREFERENCED_PARAMETER( isTimeToStop );

    if( rpal_memory_isValid( criticalStub ) )
    {
        if( _removeEventId( &g_critical_adhoc, *criticalStub ) )
        {
            rpal_debug_info( "removing adhoc critical (expired): %d", *criticalStub );
        }

        rpal_memory_free( criticalStub );
    }

    return NULL;
}

static
RVOID
    add_critical
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;
    RTIME expire = 0;
    rpcm_tag* criticalStub = NULL;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _addEventId( &g_critical_adhoc, eventId ) )
            {
                rpal_debug_info( "adding adhoc critical: %d", eventId );

                if( rSequence_getTIMESTAMP( event, RP_TAGS_EXPIRY, &expire ) )
                {
                    if( NULL != ( criticalStub = rpal_memory_alloc( sizeof( *criticalStub ) ) ) )
                    {
                        *criticalStub = eventId;
                        if( !rThreadPool_scheduleOneTime( g_state->hThreadPool,
                                                          expire,
                                                          stopCriticalCb,
                                                          criticalStub ) )
                        {
                            rpal_memory_free( criticalStub );
                        }
                        else
                        {
                            rpal_debug_info( "adding callback for expiry on new adhoc critical" );
                        }
                    }
                }
            }
        }
    }
}


static
RVOID
    del_critical
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rpcm_tag eventId = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getRU32( event, RP_TAGS_HBS_NOTIFICATION_ID, &eventId ) )
        {
            if( _removeEventId( &g_critical_adhoc, eventId ) )
            {
                rpal_debug_info( "removing adhoc critical: %d", eventId );
            }
        }
    }
}


static
RVOID
    get_critical
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    rList events = NULL;
    RU32 i = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) )
    {
        if( rMutex_lock( g_critical_adhoc.mutex ) )
        {
            if( NULL != ( events = rList_new( RP_TAGS_HBS_NOTIFICATION_ID, RPCM_RU32 ) ) )
            {
                if( rpal_memory_isValid( g_critical_adhoc.pElems ) )
                {
                    for( i = 0; i < g_critical_adhoc.nElem; i++ )
                    {
                        rList_addRU32( events, g_critical_adhoc.pElems[ i ] );
                    }
                }

                if( !rSequence_addLIST( event, RP_TAGS_HBS_LIST_NOTIFICATIONS, events ) )
                {
                    rList_free( events );
                    events = NULL;
                }

                notifications_publish( RP_TAGS_NOTIFICATION_GET_CRITICAL_EVENT_REP, event );
            }

            rMutex_unlock( g_critical_adhoc.mutex );
        }
    }
}


//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_0_events[] = { RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REP,
                                  RP_TAGS_NOTIFICATION_GET_CRITICAL_EVENT_REP,
                                  0 };

RBOOL
    collector_0_init
    ( 
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    rList subscribed = NULL;
    rpcm_tag notifId = 0;
    RU32 i = 0;
    RU32 j = 0;

    if( NULL != hbsState )
    {
        if( NULL != ( g_history_mutex = rMutex_create() ) &&
            _initEventList( &g_exfil_profile ) &&
            _initEventList( &g_exfil_adhoc ) &&
            _initEventList( &g_critical_profile ) &&
            _initEventList( &g_critical_adhoc ) )
        {
            isSuccess = TRUE;
            g_state = hbsState;

            rpal_memory_zero( g_history, sizeof( g_history ) );
            g_cur_size = 0;
            g_history_head = 0;

            if( notifications_subscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         add_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         del_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         get_exfil ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_ADD_CRITICAL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         add_critical ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_DEL_CRITICAL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         del_critical ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_GET_CRITICAL_EVENT_REQ,
                                         NULL,
                                         0,
                                         NULL,
                                         get_critical ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, 
                                         NULL, 
                                         0, 
                                         NULL, 
                                         dumpHistory ) )
            {
                // First we register for all the external events of all the collectors.
                // We will triage as they come in.
                for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
                {
                    j = 0;

                    while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                    {
                        if( !notifications_subscribe( g_state->collectors[ i ].externalEvents[ j ],
                                                      NULL, 0, NULL, exfilFunc ) )
                        {
                            rpal_debug_error( "error subscribing to event %d for exfil management",
                                              g_state->collectors[ i ].externalEvents[ j ] );
                            isSuccess = FALSE;
                        }

                        j++;
                    }
                }

                // Next we assemble the list of events for profile exfil.
                if( rpal_memory_isValid( config ) &&
                    rSequence_getLIST( config, RP_TAGS_HBS_LIST_NOTIFICATIONS, &subscribed ) )
                {
                    while( rList_getRU32( subscribed, RP_TAGS_HBS_NOTIFICATION_ID, &notifId ) )
                    {
                        if( !_addEventId( &g_exfil_profile, notifId ) )
                        {
                            isSuccess = FALSE;
                        }
                    }
                }

                // Finally we get the list of critical events.
                if( rpal_memory_isValid( config ) &&
                    rSequence_getLIST( config, RP_TAGS_HBS_CRITICAL_EVENTS, &subscribed ) )
                {
                    while( rList_getRU32( subscribed, RP_TAGS_HBS_NOTIFICATION_ID, &notifId ) )
                    {
                        if( !_addEventId( &g_critical_profile, notifId ) )
                        {
                            isSuccess = FALSE;
                        }
                    }
                }
            }
        }

        if( !isSuccess )
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, NULL, add_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, NULL, del_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, NULL, get_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_CRITICAL_EVENT_REQ, NULL, add_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_CRITICAL_EVENT_REQ, NULL, del_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_CRITICAL_EVENT_REQ, NULL, get_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, NULL, dumpHistory );

            for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
            {
                j = 0;

                while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                {
                    notifications_unsubscribe( g_state->collectors[ i ].externalEvents[ j ], 
                                               NULL, exfilFunc );

                    j++;
                }
            }

            rMutex_free( g_history_mutex );
            g_history_mutex = NULL;
            _deinitEventList( &g_exfil_profile );
            _deinitEventList( &g_exfil_adhoc );
            _deinitEventList( &g_critical_profile );
            _deinitEventList( &g_critical_adhoc );
        }
    }

    return isSuccess;
}

RBOOL 
    collector_0_cleanup
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
        if( rMutex_lock( g_history_mutex ) )
        {
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_EXFIL_EVENT_REQ, NULL, add_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_EXFIL_EVENT_REQ, NULL, del_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_EXFIL_EVENT_REQ, NULL, get_exfil );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_ADD_CRITICAL_EVENT_REQ, NULL, add_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DEL_CRITICAL_EVENT_REQ, NULL, del_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_CRITICAL_EVENT_REQ, NULL, get_critical );
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_HISTORY_DUMP_REQ, NULL, dumpHistory );

            for( i = 0; i < ARRAY_N_ELEM( g_state->collectors ); i++ )
            {
                j = 0;

                while( 0 != g_state->collectors[ i ].externalEvents[ j ] )
                {
                    notifications_unsubscribe( g_state->collectors[ i ].externalEvents[ j ],
                                               NULL, 
                                               exfilFunc );

                    j++;
                }
            }

            for( i = 0; i < ARRAY_N_ELEM( g_history ); i++ )
            {
                if( rpal_memory_isValid( g_history[ i ] ) )
                {
                    rSequence_free( g_history[ i ] );
                    g_history[ i ] = NULL;
                }
            }

            g_cur_size = 0;
            g_history_head = 0;

            rMutex_free( g_history_mutex );
            g_history_mutex = NULL;
            _deinitEventList( &g_exfil_profile );
            _deinitEventList( &g_exfil_adhoc );
            _deinitEventList( &g_critical_profile );
            _deinitEventList( &g_critical_adhoc );
        }
    }

    return isSuccess;
}
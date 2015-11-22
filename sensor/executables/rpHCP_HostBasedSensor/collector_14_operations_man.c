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

static HbsState* g_hbsStateRef = NULL;

static
RVOID
    remain_live
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    RTIME expiry = 0;

    UNREFERENCED_PARAMETER( eventType );

    if( rpal_memory_isValid( event ) &&
        NULL != g_hbsStateRef )
    {
        if( rSequence_getTIMESTAMP( event, RP_TAGS_EXPIRY, &expiry ) )
        {
            rInterlocked_set64( &( g_hbsStateRef->liveUntil ), expiry );
            rpal_debug_info( "going live until %ld", expiry );
        }
    }
}

RBOOL
    collector_14_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        g_hbsStateRef = hbsState;

        if( notifications_subscribe( RP_TAGS_NOTIFICATION_REMAIN_LIVE_REQ,
                                     NULL,
                                     0,
                                     NULL,
                                     remain_live ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

RBOOL
    collector_14_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_REMAIN_LIVE_REQ, NULL, remain_live );

        g_hbsStateRef = NULL;
        isSuccess = TRUE;
    }

    return isSuccess;
}

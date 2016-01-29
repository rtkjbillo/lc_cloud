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

#include "collectors.h"
#include <rpHostCommonPlatformLib/rTags.h>
#include <libOs/libOs.h>

RBOOL
    hbs_markAsRelated
    (
        rSequence parent,
        rSequence toMark
    )
{
    RBOOL isSuccess = FALSE;
    RPCHAR invId = NULL;

    if( rpal_memory_isValid( parent ) &&
        rpal_memory_isValid( toMark ) )
    {
        isSuccess = TRUE;

        if( rSequence_getSTRINGA( parent, RP_TAGS_HBS_INVESTIGATION_ID, &invId ) )
        {
            isSuccess = FALSE;
            if( rSequence_addSTRINGA( toMark, RP_TAGS_HBS_INVESTIGATION_ID, invId ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

RBOOL
    hbs_whenCpuBelow
    (
        RU8 percent,
        RTIME timeoutSeconds,
        rEvent abortEvent
    )
{
    RBOOL isCpuIdle = FALSE;

    RTIME end = rpal_time_getLocal() + timeoutSeconds;

    do
    {
        if( libOs_getCpuUsage() <= percent )
        {
            isCpuIdle = TRUE;
            break;
        }

        if( NULL == abortEvent )
        {
            rpal_thread_sleep( MSEC_FROM_SEC( 1 ) );
        }
        else
        {
            if( rEvent_wait( abortEvent, MSEC_FROM_SEC( 1 ) ) )
            {
                break;
            }
        }
    } 
    while( end > rpal_time_getLocal() );

    return isCpuIdle;
}
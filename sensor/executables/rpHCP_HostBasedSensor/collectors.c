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

#define RPAL_FILE_ID        103

typedef struct
{
    rCollection col;
    RU32 sizeInBuffer;
    RU32 nMaxElements;
    RU32 maxTotalSize;

} _HbsRingBuffer;

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
    hbs_timestampEvent
    (
        rSequence event,
        RTIME optOriginal
    )
{
    RBOOL isTimestamped = FALSE;
    RTIME ts = 0;

    if( NULL != event )
    {
        if( 0 != optOriginal )
        {
            ts = optOriginal;
        }
        else
        {
            ts = rpal_time_getGlobalPreciseTime();
        }

        isTimestamped = rSequence_addTIMESTAMP( event, RP_TAGS_TIMESTAMP, ts );
    }

    return isTimestamped;
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

HbsRingBuffer
    HbsRingBuffer_new
    (
        RU32 nMaxElements,
        RU32 maxTotalSize
    )
{
    _HbsRingBuffer* hrb = NULL;

    if( NULL != ( hrb = rpal_memory_alloc( sizeof( _HbsRingBuffer ) ) ) )
    {
        if( rpal_collection_create( &hrb->col, _freeEvt ) )
        {
            hrb->sizeInBuffer = 0;
            hrb->nMaxElements = nMaxElements;
            hrb->maxTotalSize = maxTotalSize;
        }
        else
        {
            rpal_memory_free( hrb );
            hrb = NULL;
        }
    }

    return (HbsRingBuffer)hrb;
}

RVOID
    HbsRingBuffer_free
    (
        HbsRingBuffer hrb
    )
{
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;
    
    if( rpal_memory_isValid( pHrb ) )
    {
        if( NULL != pHrb->col )
        {
            rpal_collection_free( pHrb->col );
        }

        rpal_memory_free( pHrb );
    }
}

RBOOL
    HbsRingBuffer_add
    (
        HbsRingBuffer hrb,
        rSequence elem
    )
{
    RBOOL isAdded = FALSE;
    RBOOL isReadyToAdd = FALSE;
    RU32 elemSize = 0;
    rSequence toDelete = NULL;
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;

    if( rpal_memory_isValid( hrb ) &&
        rpal_memory_isValid( elem ) )
    {
        elemSize = rSequence_getEstimateSize( elem );

        isReadyToAdd = TRUE;

        while( ( 0 != pHrb->maxTotalSize &&
                 elemSize + pHrb->sizeInBuffer > pHrb->maxTotalSize ) ||
               ( 0 != pHrb->nMaxElements &&
                 rpal_collection_getSize( pHrb->col ) + 1 > pHrb->nMaxElements ) )
        {
            if( rpal_collection_remove( pHrb->col, &toDelete, NULL, NULL, NULL ) )
            {
                rSequence_free( toDelete );
            }
            else
            {
                isReadyToAdd = FALSE;
                break;
            }
        }

        if( isReadyToAdd &&
            rpal_collection_add( pHrb->col, elem, sizeof( elem ) ) )
        {
            isAdded = TRUE;
            pHrb->sizeInBuffer += rSequence_getEstimateSize( elem );
        }
    }

    return isAdded;
}

typedef struct
{
    RBOOL( *compareFunction )( rSequence seq, RPVOID ref );
    RPVOID ref;
    rSequence last;

} _ShimCompareContext;

static
RBOOL
    _shimCompareFunction
    (
        rSequence seq,
        RU32 dummySize,
        _ShimCompareContext* ctx
    )
{
    RBOOL ret = FALSE;
    UNREFERENCED_PARAMETER( dummySize );

    if( NULL != seq &&
        NULL != ctx )
    {
        // If the out value of the find contained a non-null
        // pointer we use it as an iterator marker and will
        // only report hits we find AFTER we've seen the marker.
        // This means that a new call to find should always
        // use NULL as an initial value in the pFound but also
        // that if you use it as an iterator you cannot remove
        // the last found value in between calls.
        if( NULL != ctx->last )
        {
            if( ctx->last == seq )
            {
                ctx->last = NULL;
            }
        }
        else
        {
            ret = ctx->compareFunction( seq, ctx->ref );
        }
    }

    return ret;
}

RBOOL
    HbsRingBuffer_find
    (
        HbsRingBuffer hrb,
        RBOOL( *compareFunction )( rSequence seq, RPVOID ref ),
        RPVOID ref,
        rSequence* pFound
    )
{
    RBOOL isFound = FALSE;
    _HbsRingBuffer* pHrb = (_HbsRingBuffer*)hrb;
    _ShimCompareContext ctx = { 0 };

    if( rpal_memory_isValid( hrb ) &&
        NULL != compareFunction &&
        NULL != pFound )
    {
        ctx.compareFunction = compareFunction;
        ctx.ref = ref;

        if( NULL != *pFound )
        {
            ctx.last = *pFound;
        }

        if( rpal_collection_get( pHrb->col, pFound, NULL, (collection_compare_func)_shimCompareFunction, &ctx ) )
        {
            isFound = TRUE;
        }
    }

    return isFound;
}
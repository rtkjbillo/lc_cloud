#include "stateful_widgets.h"
#include <rpal/rpal.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define RPAL_FILE_ID        107

//=============================================================================
//  BOILERPLATE
//=============================================================================
#define GENERAL_EXPECTED_DELAY      (30)

typedef struct _SAMWidget
{
    RVOID( *freeFunc )( struct _SAMWidget* self );
    SAMStateVector*( *propagateNewEvent )( struct _SAMWidget* self, SAMEvent* event );
    rVector feeds;
} SAMWidget;

#define PROPAGATE(widget,event) ((SAMWidget*)(widget))->propagateNewEvent((widget),(event))

typedef struct _SAMFilterWidget
{
    SAMWidget widget;
    RBOOL( *executeNewEvent )( struct _SAMFilterWidget* self, SAMEvent* event );
} SAMFilterWidget;

#define EXECUTE_EVENT(widget,event) ((SAMFilterWidget*)(widget))->executeNewEvent((widget),(event))

typedef struct _SAMStateWidget
{
    SAMWidget widget;
    SAMStateVector*( *processStates )( struct _SAMStateWidget* self, rVector statesVector );
    RVOID( *garbageCollect )( struct _SAMStateWidget* self, rVector statesVector );
    rVector statesVector;
    SAMStateVector* lastOutput;
} SAMStateWidget;

#define PROCESS_STATES(widget) ((SAMStateWidget*)(widget))->processStates((widget), (widget)->statesVector)
#define GARBAGE_COLLECT(widget) ((SAMStateWidget*)(widget))->garbageCollect((widget), (widget)->statesVector)

static
SAMState*
    SAMState_new
    (

    )
{
    SAMState* state = NULL;
    
    if( NULL != ( state = rpal_memory_alloc( sizeof( SAMState ) ) ) )
    {
        if( NULL != ( state->events = rpal_vector_new() ) )
        {
            state->tsEarliest = (RU32)(-1);
            state->tsLatest = 0;
        }
        else
        {
            rpal_memory_free( state );
            state = NULL;
        }
    }

    return state;
}

static
RVOID
    SAMState_free
    (
        SAMState* state
    )
{
    RU32 i = 0;

    if( NULL != state )
    {
        if( NULL != state->events )
        {
            for( i = 0; i < state->events->nElements; i++ )
            {
                rRefCount_release( ( (SAMEvent*)state->events->elements[ i ] )->ref, NULL );
            }

            rpal_vector_free( state->events );
        }
        rpal_memory_free( state );
    }
}

static
RBOOL
    SAMState_add
    (
        SAMState* state,
        SAMEvent* event
    )
{
    RBOOL isAdded = FALSE;

    if( NULL != state &&
        NULL != event )
    {
        if( rpal_vector_add( state->events, event ) &&
            rRefCount_acquire( event->ref ) )
        {
            if( event->ts > state->tsLatest )
            {
                state->tsLatest = event->ts;
            }

            if( event->ts < state->tsEarliest )
            {
                state->tsEarliest = event->ts;
            }
            isAdded = TRUE;
        }
    }

    return isAdded;
}


static
SAMState*
    SAMState_duplicate
    (
        SAMState* state
    )
{
    SAMState* newState = NULL;
    RU32 i = 0;

    if( NULL != state )
    {
        if( NULL != ( newState = SAMState_new() ) )
        {
            for( i = 0; i < state->events->nElements; i++ )
            {
                SAMState_add( newState, state->events->elements[ i ] );
            }
        }
    }

    return newState;
}

static
SAMStateVector*
    SAMStateVector_new
    (

    )
{
    SAMStateVector* statev = NULL;

    if( NULL != ( statev = rpal_memory_alloc( sizeof( SAMStateVector ) ) ) )
    {
        if( NULL != ( statev->states = rpal_vector_new() ) )
        {
            statev->isDirty = FALSE;
        }
        else
        {
            rpal_memory_free( statev );
            statev = NULL;
        }
    }

    return statev;
}

RVOID
    SAMStateVector_free
    (
        SAMStateVector* statev
    )
{
    RU32 i = 0;

    if( NULL != statev )
    {
        if( NULL != statev->states )
        {
            for( i = 0; i < statev->states->nElements; i++ )
            {
                SAMState_free( statev->states->elements[ i ] );
            }
            rpal_vector_free( statev->states );
        }
        rpal_memory_free( statev );
    }
}


RVOID
    SAMStateVector_shallowFree
    (
        SAMStateVector* statev
    )
{
    if( NULL != statev )
    {
        if( NULL != statev->states )
        {
            rpal_vector_free( statev->states );
        }
        rpal_memory_free( statev );
    }
}


static
RBOOL
    SAMStateVector_add
    (
        SAMStateVector* statev,
        SAMState* state
    )
{
    RBOOL isAdded = FALSE;

    if( NULL != statev &&
        NULL != state )
    {
        if( rpal_vector_add( statev->states, state ) )
        {
            isAdded = TRUE;
            statev->isDirty = TRUE;
        }
    }

    return isAdded;
}

static
RBOOL
    SAMStateVector_removeState
    (
        SAMStateVector* statev,
        RU32 indexToRemove
    )
{
    RBOOL isRemoved = FALSE;

    if( NULL != statev )
    {
        if( indexToRemove >= 0 &&
            indexToRemove < statev->states->nElements )
        {
            SAMState_free( statev->states->elements[ indexToRemove ] );

            if( rpal_vector_remove( statev->states, indexToRemove ) )
            {
                isRemoved = TRUE;
            }
        }
    }

    return isRemoved;
}


static
RBOOL
    SAMStateVector_merge
    (
        SAMStateVector* toKeep,
        SAMStateVector* toMergeIn
    )
{
    RBOOL isMerged = FALSE;
    RU32 i = 0;

    if( NULL != toKeep &&
        NULL != toMergeIn )
    {
        for( i = 0; i < toMergeIn->states->nElements; i++ )
        {
            SAMStateVector_add( toKeep, toMergeIn->states->elements[ i ] );
        }

        SAMStateVector_shallowFree( toMergeIn );
        isMerged = TRUE;
    }

    return isMerged;
}

static
SAMStateVector*
    SAMStateVector_duplicate
    (
        SAMStateVector* statev
    )
{
    SAMStateVector* newVector = NULL;
    RU32 i = 0;

    if( NULL != statev )
    {
        if( NULL != ( newVector = SAMStateVector_new() ) )
        {
            for( i = 0; i < statev->states->nElements; i++ )
            {
                SAMStateVector_add( newVector, statev->states->elements[ i ] );
            }
        }
    }

    return newVector;
}

static
rVector
    flattenStateVector
    (
        SAMStateVector* v
    )
{
    rVector newV = NULL;
    RU32 i = 0;
    RU32 j = 0;
    SAMState* tmpState = NULL;
    SAMEvent* tmpEvent = NULL;

    if( NULL != v )
    {
        if( NULL != ( newV = rpal_vector_new() ) )
        {
            for( i = 0; i < v->states->nElements; i++ )
            {
                tmpState = v->states->elements[ i ];
                for( j = 0; j < tmpState->events->nElements; j++ )
                {
                    tmpEvent = tmpState->events->elements[ j ];
                    rpal_vector_add( newV, tmpEvent );
                }
            }
        }
    }

    return newV;
}

static
rVector
    flattenStatesVector
    (
        rVector v
    )
{
    RU32 i = 0;
    RU32 j = 0;
    RU32 k = 0;
    rVector newV = NULL;
    SAMStateVector* tmpVector = NULL;
    SAMState* tmpState = NULL;
    SAMEvent* tmpEvent = NULL;

    if( NULL != v )
    {
        if( NULL != ( newV = rpal_vector_new() ) )
        {
            for( i = 0; i < v->nElements; i++ )
            {
                tmpVector = v->elements[ i ];
                for( j = 0; j < tmpVector->states->nElements; j++ )
                {
                    tmpState = tmpVector->states->elements[ j ];
                    for( k = 0; k < tmpState->events->nElements; k++ )
                    {
                        tmpEvent = tmpState->events->elements[ k ];
                        rpal_vector_add( newV, tmpEvent );
                    }
                }
            }
        }
    }

    return newV;
}

static
RVOID
    SAMEvent_free
    (
        SAMEvent* event,
        RU32 size
    )
{
    UNREFERENCED_PARAMETER( size );

    if( NULL != event )
    {
        if( NULL != event->event )
        {
            rSequence_free( event->event );
            event->event = NULL;
        }
    }
}

SAMEvent*
    SAMEvent_new
    (
        rpcm_tag eventType,
        rSequence event
    )
{
    SAMEvent* ev = NULL;

    if( NULL != event )
    {
        if( NULL != ( ev = rpal_memory_alloc( sizeof( SAMEvent ) ) ) )
        {
            ev->event = rSequence_duplicate( event );
            ev->eventType = eventType;
            ev->ref = rRefCount_create( SAMEvent_free, ev, sizeof( SAMEvent ) );
            rSequence_getTIMESTAMP( event, RP_TAGS_TIMESTAMP, &ev->ts );
        }
    }

    return ev;
}

static
RS32
    _cmpPtr
    (
        RPVOID p1,
        RPVOID p2
    )
{
    return (RS32)((RPU8)p1 - (RPU8)p2);
}

static
RBOOL
    isOutputChanged
    (
        SAMStateVector* lastOutput,
        SAMStateVector* newOutput
    )
{
    RBOOL isChanged = FALSE;
    rVector flat1 = NULL;
    rVector flat2 = NULL;
    RU32 i = 0;

    if( NULL != newOutput )
    {
        if( NULL == lastOutput ||
            lastOutput->states->nElements != newOutput->states->nElements )
        {
            isChanged = TRUE;
        }
        else
        {
            if( NULL != ( flat1 = flattenStateVector( lastOutput ) ) &&
                NULL != ( flat2 = flattenStateVector( newOutput ) ) )
            {
                rpal_sort_array( flat1,
                                 flat1->nElements,
                                 sizeof( RPVOID ),
                                 _cmpPtr );

                rpal_sort_array( flat2,
                                 flat2->nElements,
                                 sizeof( RPVOID ),
                                 _cmpPtr );

                for( i = 0; i < flat1->nElements; i++ )
                {
                    if( flat1->elements[ i ] != flat2->elements[ i ] )
                    {
                        isChanged = TRUE;
                        break;
                    }
                }
            }

            rpal_vector_free( flat1 );
            rpal_vector_free( flat2 );
        }
    }

    return isChanged;
}

static
RVOID
    SAMWidgetFree
    (
        SAMWidget* self
    )
{
    RU32 i = 0;

    if( NULL != self )
    {
        if( NULL != self->feeds )
        {
            for( i = 0; i < self->feeds->nElements; i++ )
            {
                ( (SAMWidget*)self->feeds->elements[ i ] )->freeFunc( self->feeds->elements[ i ] );
            }

            rpal_vector_free( self->feeds );
        }

        rpal_memory_free( self );
    }
}

static
RVOID
    SAMWidgetInit
    (
        SAMWidget* self
    )
{
    if( NULL != self )
    {
        self->feeds = rpal_vector_new();
        self->freeFunc = SAMWidgetFree;
        self->propagateNewEvent = NULL; // Must be defined by Filters or State
    }
}


static
RVOID
    SAMFilterWidgetFree
    (
        SAMFilterWidget* self
    )
{
    if( NULL != self )
    {
        // No local storage for Filters, pass on to Widget
        SAMWidgetFree( (SAMWidget*)self );
    }
}

static
SAMStateVector*
    SAMFilterWidgetPropagate
    (
        SAMFilterWidget* self,
        SAMEvent* event
    )
{
    SAMStateVector* states = NULL;
    SAMState* state = NULL;
    SAMStateVector* feedStates = NULL;
    RBOOL isProducing = FALSE;
    RU32 i = 0;
    RU32 j = 0;
    RU32 k = 0;
    SAMState* tmpState = NULL;

    if( NULL != self )
    {
        if( 0 == self->widget.feeds->nElements )
        {
            if( EXECUTE_EVENT( self, event ) )
            {
                // Event needs to be produced
                if( NULL != ( states = SAMStateVector_new() ) )
                {
                    if( NULL != ( state = SAMState_new() ) )
                    {
                        if( SAMStateVector_add( states, state ) )
                        {
                            if( SAMState_add( state, event ) )
                            {
                                isProducing = TRUE;
                            }
                        }
                    }
                }
            }
            else
            {
                // Event is not of interest
            }
        }
        else
        {
            for( i = 0; i < self->widget.feeds->nElements; i++ )
            {
                if( NULL != ( feedStates = PROPAGATE( self->widget.feeds->elements[ i ], event ) ) )
                {
                    for( j = 0; j < feedStates->states->nElements; j++ )
                    {
                        state = feedStates->states->elements[ j ];
                        for( k = 0; k < state->events->nElements; k++ )
                        {
                            event = state->events->elements[ k ];
                            if( EXECUTE_EVENT( self, event ) )
                            {
                                if( NULL == states )
                                {
                                    states = SAMStateVector_new();
                                }

                                if( NULL != ( tmpState = SAMState_new() ) )
                                {
                                    if( !SAMState_add( tmpState, event ) ||
                                        !SAMStateVector_add( states, tmpState ) )
                                    {
                                        SAMState_free( tmpState );
                                    }
                                    else
                                    {
                                        isProducing = TRUE;
                                    }
                                }
                            }
                        }
                    }

                    SAMStateVector_free( feedStates );
                }
            }
        }

        if( !isProducing &&
            NULL != states )
        {
            SAMStateVector_free( states );
            states = NULL;
        }
    }

    return states;
}

static
RVOID
    SAMFilterWidgetInit
    (
        SAMFilterWidget* self
    )
{
    if( NULL != self )
    {
        SAMWidgetInit( (SAMWidget*)self );
        self->widget.propagateNewEvent = (SAMStateVector*(*)(SAMWidget*, SAMEvent*)) SAMFilterWidgetPropagate;
        self->executeNewEvent = NULL;
    }
}

static
RBOOL
    SAMFilterWidget_AddFeed
    (
        SAMFilterWidget* self,
        SAMWidget* widget
    )
{
    RBOOL isSuccess = FALSE;
    
    if( NULL != self &&
        NULL != widget )
    {
        if( rpal_vector_add( self->widget.feeds, widget ) )
        {
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

static
RVOID
    SAMStateWidgetFree
    (
        SAMStateWidget* self
    )
{
    RU32 i = 0;

    if( NULL != self )
    {
        for( i = 0; i < self->statesVector->nElements; i++ )
        {
            SAMStateVector_free( self->statesVector->elements[ i ] );
        }

        rpal_vector_free( self->statesVector );

        SAMWidgetFree( (SAMWidget*)self );
    }
}

static
SAMStateVector*
    SAMStateWidgetPropagate
    (
        SAMStateWidget* self,
        SAMEvent* event
    )
{
    SAMStateVector* feedStates = NULL;
    RU32 i = 0;
    RBOOL isNewInput = FALSE;
    SAMStateVector* output = NULL;

    if( NULL != self )
    {
        for( i = 0; i < self->widget.feeds->nElements; i++ )
        {
            if( NULL != ( feedStates = PROPAGATE( self->widget.feeds->elements[ i ], event ) ) )
            {
                isNewInput = TRUE;

                SAMStateVector_merge( self->statesVector->elements[ i ], feedStates );
            }
        }

        if( isNewInput )
        {
            if( NULL != ( output = PROCESS_STATES( self ) ) )
            {
                if( !isOutputChanged( self->lastOutput, output ) )
                {
                    SAMStateVector_free( output );
                    output = NULL;
                }
                else
                {
                    if( NULL != self->lastOutput )
                    {
                        SAMStateVector_free( self->lastOutput );
                    }
                    self->lastOutput = SAMStateVector_duplicate( output );
                }
            }
        }

        if( NULL != self->garbageCollect )
        {
            GARBAGE_COLLECT( self );
        }
    }

    return output;
}

static
RVOID
    SAMStateWidgetInit
    (
        SAMStateWidget* self
    )
{
    if( NULL != self )
    {
        SAMWidgetInit( (SAMWidget*)self );
        self->widget.propagateNewEvent = (SAMStateVector*(*)(SAMWidget*, SAMEvent*))SAMStateWidgetPropagate;
        self->widget.freeFunc = (RVOID(*)(SAMWidget*))SAMStateWidgetFree;
        self->processStates = NULL;
        self->garbageCollect = NULL;
        self->statesVector = rpal_vector_new();
    }
}

static
RBOOL
    SAMStateWidget_AddFeed
    (
        SAMStateWidget* self,
        SAMWidget* widget
    )
{
    RBOOL isSuccess = FALSE;
    SAMStateVector* tmpStates = NULL;

    if( NULL != self &&
        NULL != widget )
    {
        if( NULL != ( tmpStates = SAMStateVector_new() ) &&
            rpal_vector_add( self->widget.feeds, widget ) &&
            rpal_vector_add( self->statesVector, tmpStates ) )
        {
            isSuccess = TRUE;
        }
        else if( NULL != tmpStates )
        {
            SAMStateVector_free( tmpStates );
        }
    }

    return isSuccess;
}

RVOID
    SAMFree
    (
        StatefulWidget widget
    )
{
    if( NULL != widget )
    {
        ( (SAMWidget*)widget )->freeFunc( widget );
    }
}


SAMStateVector*
    SAMUpdate
    (
        StatefulWidget widget,
        SAMEvent* samEvent
    )
{
    SAMStateVector* results = NULL;

    if( NULL != widget &&
        NULL != samEvent )
    {
        results = PROPAGATE( widget, samEvent );
    }

    return results;
}

//=============================================================================
//  Common Widgets
//=============================================================================

//-----------------------------------------------------------------------------
typedef struct
{
    SAMStateWidget stateWidget;
    RU32 within_sec;
    RU32 min_per_burst;
} SAMTimeBurstWidget;

static
RS32
    _CmpEventTimes
    (
        SAMEvent* event1,
        SAMEvent* event2
    )
{
    RS32 ret = 0;

    if( NULL != event1 &&
        NULL != event2 )
    {
        ret = (RS32)(event1->ts - event2->ts);
    }

    return ret;
}

SAMStateVector*
    _SAMTimeBurst_Process
    (
        SAMTimeBurstWidget* self,
        rVector statesVector
    )
{
    SAMStateVector* output = NULL;
    RU32 i = 0;
    RU32 j = 0;
    RU32 k = 0;
    RU32 lastJ = 0;
    rVector times = NULL;
    RTIME curRefTime = 0;
    RTIME endTime = 0;
    SAMState* newState = NULL;

    if( NULL != self &&
        NULL != statesVector )
    {
        if( NULL != ( times = flattenStatesVector( statesVector ) ) )
        {
            rpal_sort_array( times->elements, times->nElements, sizeof( SAMEvent* ), _CmpEventTimes );

            for( i = 0; i < times->nElements; i++ )
            {
                curRefTime = ( (SAMEvent*)times->elements[ i ] )->ts;
                for( j = i + 1; j < times->nElements; j++ )
                {
                    endTime = ( (SAMEvent*)times->elements[ j ] )->ts;
                    if( endTime > curRefTime + self->within_sec )
                    {
                        break;
                    }
                }

                if( j - i >= self->min_per_burst &&
                    j != lastJ )
                {
                    // Got a burst
                    lastJ = j;

                    if( NULL == output )
                    {
                        output = SAMStateVector_new();
                    }

                    if( NULL != output )
                    {
                        if( NULL != ( newState = SAMState_new() ) )
                        {
                            for( k = i; k < j; k++ )
                            {
                                SAMState_add( newState, times->elements[ k ] );
                            }

                            if( !SAMStateVector_add( output, newState ) )
                            {
                                SAMState_free( newState );
                            }
                        }
                    }
                }
            }

            rpal_vector_free( times );
        }
    }

    return output;
}

RVOID
    _SAMTimeBurst_Gc
    (
        SAMTimeBurstWidget* self,
        rVector statesVector
    )
{
    RU32 i = 0;
    RU32 j = 0;
    SAMStateVector* tmpVector = NULL;
    SAMState* tmpState = NULL;
    RTIME curTime = rpal_time_getGlobal();

    if( NULL != self &&
        NULL != statesVector )
    {
        for( i = 0; i < statesVector->nElements; i++ )
        {
            tmpVector = statesVector->elements[ i ];
            for( j = 0; j < tmpVector->states->nElements; j++ )
            {
                tmpState = tmpVector->states->elements[ j ];
                if( tmpState->tsLatest < ( curTime - GENERAL_EXPECTED_DELAY ) )
                {
                    if( SAMStateVector_removeState( tmpVector, j ) )
                    {
                        j--;
                    }
                }
            }
        }
    }
}

StatefulWidget
    SAMTimeBurst
    (
        RU32 within_sec,
        RU32 min_per_burst,
        StatefulWidget feed1,
        ... // NULL terminated list of feeds
    )
{
    SAMTimeBurstWidget* self = NULL;
    RP_VA_LIST ap = NULL;
    SAMWidget* tmpFeed = feed1;

    if( NULL != ( self = rpal_memory_alloc( sizeof( SAMTimeBurstWidget ) ) ) )
    {
        SAMStateWidgetInit( (SAMStateWidget*)self );
        ((SAMStateWidget*) self)->processStates = (SAMStateVector*(*)(SAMStateWidget*, rVector))_SAMTimeBurst_Process;
        ( (SAMStateWidget*)self )->garbageCollect = (RVOID(*)(SAMStateWidget*, rVector))_SAMTimeBurst_Gc;

        self->min_per_burst = min_per_burst;
        self->within_sec = within_sec;

        RP_VA_START( ap, feed1 );
        while( NULL != tmpFeed )
        {
            if( !SAMStateWidget_AddFeed( (SAMStateWidget*)self, tmpFeed ) )
            {
                SAMStateWidgetFree( (SAMStateWidget*)self );
                self = NULL;
                break;
            }

            tmpFeed = RP_VA_ARG( ap, SAMWidget* );
        }
        RP_VA_END( ap );
    }

    return self;
}
//-----------------------------------------------------------------------------
typedef struct
{
    rpcm_tag eventType;
    rpcm_type matchType;
    RPVOID matchValue;
    RU32 matchSize;
    rpcm_tag* path;
} _RpcmPathDesc;

typedef struct
{
    SAMFilterWidget filterWidget;
    _RpcmPathDesc match_path;
} SAMSimpleFilterWidget;

RBOOL
    _SAMSimpleFilter_Execute
    (
        SAMSimpleFilterWidget* self,
        SAMEvent* event
    )
{
    RBOOL isMatch = FALSE;

    rpcm_elem_record found = { 0 };
    rStack results = NULL;

    if( NULL != self &&
        NULL != event )
    {
        if( 0 == event->eventType ||
            self->match_path.eventType == event->eventType )
        {
            if( NULL != ( results = rpcm_fetchAllV( event->event,
                                                    self->match_path.matchType,
                                                    self->match_path.path ) ) )
            {
                while( rStack_pop( results, &found ) )
                {
                    if( RPCM_STRINGA == found.type )
                    {
                        isMatch = rpal_string_match( self->match_path.matchValue, found.value, FALSE );
                    }
                    else if( RPCM_STRINGW == found.type )
                    {
                        isMatch = rpal_string_matchw( self->match_path.matchValue, found.value, FALSE );
                    }
                    else if( rpcm_isElemEqual( found.type,
                                               found.value,
                                               found.size,
                                               self->match_path.matchValue,
                                               self->match_path.matchSize ) )
                    {
                        isMatch = TRUE;
                    }

                    if( isMatch )
                    {
                        break;
                    }
                }

                rStack_free( results, NULL );
            }
        }
    }

    return isMatch;
}

StatefulWidget
    SAMSimpleFilter
    (
        rpcm_tag eventType,
        RPVOID matchValue,
        RU32 matchSize,
        rpcm_type findType,
        rpcm_tag* path,
        StatefulWidget feed1,
        ...
    )
{
    SAMSimpleFilterWidget* self = NULL;
    RP_VA_LIST ap = NULL;
    SAMWidget* tmpFeed = NULL;

    if( NULL != ( self = rpal_memory_alloc( sizeof( SAMSimpleFilterWidget ) ) ) )
    {
        SAMFilterWidgetInit( (SAMFilterWidget*)self );
        ( (SAMFilterWidget*)self )->executeNewEvent = (RBOOL(*)(SAMFilterWidget*, SAMEvent*))_SAMSimpleFilter_Execute;

        self->match_path.eventType = eventType;
        self->match_path.matchValue = matchValue;
        self->match_path.matchSize = matchSize;
        self->match_path.matchType = findType;

        self->match_path.path = path;

        tmpFeed = feed1;

        RP_VA_START( ap, feed1 );
        while( NULL != tmpFeed )
        {
            if( !SAMFilterWidget_AddFeed( (SAMFilterWidget*)self, tmpFeed ) )
            {
                SAMFilterWidgetFree( (SAMFilterWidget*)self );
                self = NULL;
                break;
            }

            tmpFeed = RP_VA_ARG( ap, SAMWidget* );
        }
        RP_VA_END( ap );
    }

    return self;
}

//-----------------------------------------------------------------------------
typedef struct
{
    SAMFilterWidget filterWidget;
    RTIME olderThan;
    RTIME newerThan;
} SAMOlderOrNewerFilterWidget;

RBOOL
    _SAMOlderOrNewerFilter_Execute
    (
        SAMOlderOrNewerFilterWidget* self,
        SAMEvent* event
    )
{
    RBOOL isMatch = FALSE;

    RTIME curTime = 0;
    RTIME evtTime = 0;
    
    if( NULL != self &&
        NULL != event )
    {
        if( rSequence_getTIMESTAMP( event->event, RP_TAGS_TIMESTAMP, &evtTime ) )
        {
            curTime = rpal_time_getGlobal();

            if( ( 0 == self->olderThan ||
                  curTime - self->olderThan >= evtTime ) &&
                ( 0 == self->newerThan ||
                  curTime - self->newerThan <= evtTime ) )
            {
                isMatch = TRUE;
            }
        }
    }

    return isMatch;
}

StatefulWidget
    SAMOlderOrNewerFilter
    (
        RTIME olderThan,
        RTIME newerThan,
        StatefulWidget feed1,
        ...
    )
{
    SAMOlderOrNewerFilterWidget* self = NULL;
    RP_VA_LIST ap = NULL;
    SAMWidget* tmpFeed = NULL;

    if( NULL != ( self = rpal_memory_alloc( sizeof( SAMOlderOrNewerFilterWidget ) ) ) )
    {
        SAMFilterWidgetInit( (SAMFilterWidget*)self );
        ( (SAMFilterWidget*)self )->executeNewEvent = ( RBOOL( *)( SAMFilterWidget*, SAMEvent* ) )_SAMOlderOrNewerFilter_Execute;

        self->olderThan = olderThan;
        self->newerThan = newerThan;

        tmpFeed = feed1;

        RP_VA_START( ap, feed1 );
        while( NULL != tmpFeed )
        {
            if( !SAMFilterWidget_AddFeed( (SAMFilterWidget*)self, tmpFeed ) )
            {
                SAMFilterWidgetFree( (SAMFilterWidget*)self );
                self = NULL;
                break;
            }

            tmpFeed = RP_VA_ARG( ap, SAMWidget* );
        }
        RP_VA_END( ap );
    }

    return self;
}


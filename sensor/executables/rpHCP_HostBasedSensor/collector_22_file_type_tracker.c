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
#include <obsLib/obsLib.h>

#define  RPAL_FILE_ID           110


typedef struct
{
    RU8 atomId[ HBS_ATOM_ID_SIZE ];
    RU64 extBitMask;
    RPNCHAR processPath;

} ProcExtInfo;

static rVector g_procContexts = NULL;
static rMutex g_mutex = NULL;
static HObs g_extensions = NULL;

static
RS32
    _cmpContext
    (
        ProcExtInfo** ctx1,
        ProcExtInfo** ctx2
    )
{
    RS32 ret = 0;

    if( NULL != ctx1 &&
        NULL != ctx2 &&
        NULL != *ctx1 &&
        NULL != *ctx2 )
    {
        ret = rpal_memory_memcmp( (*ctx1)->atomId, (*ctx2)->atomId, sizeof( (*ctx1)->atomId ) );
    }

    return ret;
}

static
RBOOL
    _addPattern
    (
        HObs matcher,
        RPNCHAR pattern,
        RBOOL isSuffix,
        RPVOID context
    )
{
    RBOOL isSuccess = FALSE;
    RBOOL isCaseInsensitive = FALSE;
    RPNCHAR tmpN = NULL;
#ifdef RPAL_PLATFORM_WINDOWS
    // On Windows files and paths are not case sensitive.
    isCaseInsensitive = TRUE;
#endif
    if( rpal_string_expand( pattern, &tmpN ) )
    {
        obsLib_addStringPatternN( matcher, tmpN, isSuffix, isCaseInsensitive, context );
        rpal_memory_free( tmpN );
    }
    return isSuccess;
}

static
ProcExtInfo*
    getProcContext
    (
        RPU8 atomId
    )
{
    ProcExtInfo* procInfo = NULL;
    RU32 index = 0;

    if( (RU32)-1 != ( index = rpal_binsearch_array( g_procContexts->elements,
                                                    g_procContexts->nElements,
                                                    sizeof( ProcExtInfo* ),
                                                    &atomId,
                                                    (rpal_ordering_func)_cmpContext ) ) )
    {
        procInfo = g_procContexts->elements[ index ];
    }
    else
    {
        if( NULL != ( procInfo = rpal_memory_alloc( sizeof( *procInfo ) ) ) )
        {
            rpal_memory_memcpy( procInfo->atomId, atomId, sizeof( procInfo->atomId ) );

            if( !rpal_vector_add( g_procContexts, procInfo ) )
            {
                rpal_memory_free( procInfo );
                rpal_debug_error( "error adding new process to history" );
                procInfo = NULL;
            }
            else
            {
                rpal_sort_array( g_procContexts->elements, 
                                 g_procContexts->nElements, 
                                 sizeof( ProcExtInfo* ), 
                                 (rpal_ordering_func)_cmpContext );
            }
        }
    }

    return procInfo;
}


static
RVOID
    processNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    ProcExtInfo* ctx = NULL;
    RPNCHAR path = NULL;
    RPU8 atomId = NULL;
    RU32 size = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &path ) &&
        rSequence_getBUFFER( event, RP_TAGS_HBS_THIS_ATOM, &atomId, &size ) )
    {
        path = rpal_string_strdup( path );

        if( NULL != path &&
            rMutex_lock( g_mutex ) )
        {
            if( NULL != ctx ||
                NULL != ( ctx = getProcContext( atomId ) ) )
            {
                ctx->processPath = path;
                path = NULL;
            }
            else
            {
                rpal_debug_error( "error getting process context" );
            }

            rMutex_unlock( g_mutex );
        }

        rpal_memory_free( path );
    }
}

static
RVOID
    processTerminateProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPU8 atomId = NULL;
    RU32 size = 0;
    RU32 index = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rMutex_lock( g_mutex ) )
    {
        if( rSequence_getBUFFER( event, RP_TAGS_HBS_PARENT_ATOM, &atomId, &size ) )
        {
            if( (RU32)-1 != ( index = rpal_binsearch_array( g_procContexts->elements,
                                                            g_procContexts->nElements,
                                                            sizeof( ProcExtInfo* ),
                                                            &atomId,
                                                            (rpal_ordering_func)_cmpContext ) ) )
            {
                rpal_memory_free( ( (ProcExtInfo*)g_procContexts->elements[ index ] )->processPath );
                rpal_memory_free( g_procContexts->elements[ index ] );
                rpal_vector_remove( g_procContexts, index );
            }
        }

        rMutex_unlock( g_mutex );
    }
}

static
RVOID
    processFileIo
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    ProcExtInfo* ctx = NULL;
    RPNCHAR path = NULL;
    RPVOID patternCtx = 0;
    RU8 patternId = 0;
    RPU8 atomId = NULL;
    RU32 size = 0;
    RU32 pid = 0;
    rSequence newEvent = NULL;

    UNREFERENCED_PARAMETER( notifType );

    if( rSequence_getSTRINGN( event, RP_TAGS_FILE_PATH, &path ) &&
        rSequence_getBUFFER( event, RP_TAGS_HBS_PARENT_ATOM, &atomId, &size ) &&
        rSequence_getRU32( event, RP_TAGS_PROCESS_ID, &pid ) )
    {
        if( rMutex_lock( g_mutex ) )
        {
            obsLib_resetSearchState( g_extensions );
            if( obsLib_setTargetBuffer( g_extensions,
                                        path,
                                        rpal_string_strsize( path ) ) )
            {
                while( obsLib_nextHit( g_extensions, &patternCtx, NULL ) )
                {
                    if( NULL != ctx ||
                        NULL != ( ctx = getProcContext( atomId ) ) )
                    {
                        patternId = (RU8)PTR_TO_NUMBER( patternCtx );

                        if( !IS_FLAG_ENABLED( ctx->extBitMask, (RU64)1 << patternId ) )
                        {
                            rpal_debug_info( "process " RF_U32 " observed file io " RF_U64, 
                                             pid, patternId + 1 );
                            ENABLE_FLAG( ctx->extBitMask, (RU64)1 << patternId );
                            
                            if( NULL != ( newEvent = rSequence_new() ) )
                            {
                                rSequence_addBUFFER( newEvent, RP_TAGS_HBS_PARENT_ATOM, atomId, size );
                                rSequence_addRU32( newEvent, RP_TAGS_PROCESS_ID, pid );
                                rSequence_addRU8( newEvent, RP_TAGS_RULE_NAME, patternId + 1 );
                                rSequence_addSTRINGN( newEvent, RP_TAGS_FILE_PATH, ctx->processPath );

                                hbs_publish( RP_TAGS_NOTIFICATION_FILE_TYPE_ACCESSED, newEvent );
                                rSequence_free( newEvent );
                            }
                        }
                    }
                    else
                    {
                        rpal_debug_error( "error getting process context" );
                        break;
                    }
                }
            }

            rMutex_unlock( g_mutex );
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_22_events[] = { RP_TAGS_NOTIFICATION_FILE_TYPE_ACCESSED,
                                   0 };

RBOOL
    collector_22_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    rList patterns = NULL;
    rSequence pattern = NULL;
    RPCHAR strA = NULL;
    RPWCHAR strW = NULL;
    RPNCHAR tmpN = NULL;
    RU8 patternId = 0;
    RU32 i = 0;

    if( NULL != hbsState &&
        NULL != ( g_extensions = obsLib_new( 0, 0 ) ) )
    {
        if( rSequence_getLIST( config, RP_TAGS_PATTERNS, &patterns ) )
        {
            while( rList_getSEQUENCE( patterns, RP_TAGS_RULE, &pattern ) )
            {
                if( rSequence_getRU8( pattern, RP_TAGS_RULE_NAME, &patternId ) )
                {
                    if( 64 < patternId || 0 == patternId )
                    {
                        rpal_debug_critical( "rule id must be below 64 and 1-based." );
                        continue;
                    }

                    // Base the pattern id to 0
                    patternId--;

                    if( rSequence_getSTRINGA( pattern, RP_TAGS_EXTENSION, &strA ) &&
                        NULL != ( tmpN = rpal_string_aton( strA ) ) )
                    {
                        _addPattern( g_extensions, tmpN, TRUE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGW( pattern, RP_TAGS_EXTENSION, &strW ) &&
                        NULL != ( tmpN = rpal_string_wton( strW ) ) )
                    {
                        _addPattern( g_extensions, tmpN, TRUE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGA( pattern, RP_TAGS_STRING_PATTERN, &strA ) &&
                        NULL != ( tmpN = rpal_string_aton( strA ) ) )
                    {
                        _addPattern( g_extensions, tmpN, FALSE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }

                    if( rSequence_getSTRINGW( pattern, RP_TAGS_STRING_PATTERN, &strW ) &&
                        NULL != ( tmpN = rpal_string_wton( strW ) ) )
                    {
                        _addPattern( g_extensions, tmpN, FALSE, NUMBER_TO_PTR( patternId ) );
                        rpal_memory_free( tmpN );
                    }
                }
            }

            if( NULL != ( g_mutex = rMutex_create() ) &&
                NULL != ( g_procContexts = rpal_vector_new() ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, 0, NULL, processFileIo ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, processNewProcesses ) &&
                notifications_subscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, 0, NULL, processTerminateProcesses ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    if( !isSuccess )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, processTerminateProcesses );
        obsLib_free( g_extensions );
        g_extensions = NULL;
        for( i = 0; i < g_procContexts->nElements; i++ )
        {
            rpal_memory_free( ( (ProcExtInfo*)g_procContexts->elements[ i ] )->processPath );
            rpal_memory_free( g_procContexts->elements[ i ] );
        }
        rpal_vector_free( g_procContexts );
        g_procContexts = NULL;
        rMutex_free( g_mutex );
        g_mutex = NULL;
    }

    return isSuccess;
}

RBOOL
    collector_22_cleanup
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
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_DELETE, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_MODIFIED, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_READ, NULL, processFileIo );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_TERMINATE_PROCESS, NULL, processTerminateProcesses );
        obsLib_free( g_extensions );
        g_extensions = NULL;
        for( i = 0; i < g_procContexts->nElements; i++ )
        {
            rpal_memory_free( ( (ProcExtInfo*)g_procContexts->elements[ i ] )->processPath );
            rpal_memory_free( g_procContexts->elements[ i ] );
        }
        rpal_vector_free( g_procContexts );
        g_procContexts = NULL;
        rMutex_free( g_mutex );
        g_mutex = NULL;

        isSuccess = TRUE;
    }

    return isSuccess;
}

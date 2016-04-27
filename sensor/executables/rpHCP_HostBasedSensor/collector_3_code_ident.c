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
#include <cryptoLib/cryptoLib.h>
#include <libOs/libOs.h>

#define RPAL_FILE_ID 72

#define _MAX_FILE_HASH_SIZE                 (1024 * 1024 * 20)

typedef struct
{
    CryptoLib_Hash nameHash;
    CryptoLib_Hash fileHash;
    RU64 codeSize;

} CodeIdent;

static rBloom g_knownCode = NULL;
static rMutex g_mutex = NULL;


static
RVOID
    processCodeIdentW
    (
        RPWCHAR name,
        CryptoLib_Hash* pFileHash,
        RU64 codeSize,
        rSequence originalEvent
    )
{
    CodeIdent ident = { 0 };
    rSequence notif = NULL;
    rSequence sig = NULL;
    RBOOL isSigned = FALSE;
    RBOOL isVerifiedLocal = FALSE;
    RBOOL isVerifiedGlobal = FALSE;
    RPWCHAR cleanPath = NULL;
    
    ident.codeSize = codeSize;

    if( NULL != name )
    {
        CryptoLib_hash( name, rpal_string_strlenw( name ) * sizeof( RWCHAR ), &ident.nameHash );
    }

    if( NULL != pFileHash )
    {
        rpal_memory_memcpy( &ident.fileHash, pFileHash, sizeof( *pFileHash ) );
    }

    if( rMutex_lock( g_mutex ) )
    {
        if( rpal_bloom_addIfNew( g_knownCode, &ident, sizeof( ident ) ) )
        {
            rMutex_unlock( g_mutex );

            if( NULL != ( notif = rSequence_new() ) )
            {
                hbs_markAsRelated( originalEvent, notif );

                if( ( rSequence_addSTRINGW( notif, RP_TAGS_FILE_PATH, name ) ||
                      rSequence_addSTRINGW( notif, RP_TAGS_DLL, name ) ||
                      rSequence_addSTRINGW( notif, RP_TAGS_EXECUTABLE, name ) ) &&
                    rSequence_addRU32( notif, RP_TAGS_MEMORY_SIZE, (RU32)codeSize ) &&
                    rSequence_addTIMESTAMP( notif, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() ) )
                {
                    if( NULL != pFileHash )
                    {
                        rSequence_addBUFFER( notif, RP_TAGS_HASH, (RPU8)pFileHash, sizeof( *pFileHash ) );
                    }

                    cleanPath = rpal_file_cleanw( name );

                    if( libOs_getSignature( cleanPath ? cleanPath : name,
                                            &sig,
                                            ( OSLIB_SIGNCHECK_NO_NETWORK | OSLIB_SIGNCHECK_CHAIN_VERIFICATION ),
                                            &isSigned,
                                            &isVerifiedLocal,
                                            &isVerifiedGlobal ) )
                    {
                        if( !rSequence_addSEQUENCE( notif, RP_TAGS_SIGNATURE, sig ) )
                        {
                            rSequence_free( sig );
                        }
                    }

                    if( NULL != cleanPath )
                    {
                        rpal_memory_free( cleanPath );
                    }

                    notifications_publish( RP_TAGS_NOTIFICATION_CODE_IDENTITY, notif );
                }
                rSequence_free( notif );
            }
        }
        else
        {
            rMutex_unlock( g_mutex );
        }
    }
}

static
RVOID
    processCodeIdentA
    (
        RPCHAR name,
        CryptoLib_Hash* pFileHash,
        RU64 codeSize,
        rSequence originalEvent
    )
{
    CodeIdent ident = { 0 };
    rSequence notif = NULL;
    rSequence sig = NULL;
    RPWCHAR wPath = NULL;
    RPWCHAR cleanPath = NULL;

    ident.codeSize = codeSize;

    if( NULL != name )
    {
        CryptoLib_hash( name, rpal_string_strlen( name ) * sizeof( RCHAR ), &ident.nameHash );
    }

    if( NULL != pFileHash )
    {
        rpal_memory_memcpy( &ident.fileHash, pFileHash, sizeof( *pFileHash ) );
    }

    if( rMutex_lock( g_mutex ) )
    {
        if( rpal_bloom_addIfNew( g_knownCode, &ident, sizeof( ident ) ) )
        {
            rMutex_unlock( g_mutex );

            if( NULL != ( notif = rSequence_new() ) )
            {
                hbs_markAsRelated( originalEvent, notif );

                if( ( rSequence_addSTRINGA( notif, RP_TAGS_FILE_PATH, name ) ||
                      rSequence_addSTRINGA( notif, RP_TAGS_DLL, name ) ||
                      rSequence_addSTRINGA( notif, RP_TAGS_EXECUTABLE, name ) ) &&
                    rSequence_addRU32( notif, RP_TAGS_MEMORY_SIZE, (RU32)codeSize ) &&
                    rSequence_addTIMESTAMP( notif, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() ) )
                {
                    if( NULL != pFileHash )
                    {
                        rSequence_addBUFFER( notif, RP_TAGS_HASH, (RPU8)pFileHash, sizeof( *pFileHash ) );
                    }

                    if( NULL != ( wPath = rpal_string_atow( name ) ) )
                    {
                        cleanPath = rpal_file_cleanw( wPath );

                        if( libOs_getSignature( cleanPath ? cleanPath : wPath, 
                                                &sig, 
                                                OSLIB_SIGNCHECK_NO_NETWORK, 
                                                NULL, 
                                                NULL, 
                                                NULL ) )
                        {
                            if( !rSequence_addSEQUENCE( notif, RP_TAGS_SIGNATURE, sig ) )
                            {
                                rSequence_free( sig );
                            }
                        }

                        if( NULL != cleanPath )
                        {
                            rpal_memory_free( cleanPath );
                        }

                        rpal_memory_free( wPath );
                    }

                    notifications_publish( RP_TAGS_NOTIFICATION_CODE_IDENTITY, notif );
                }
                rSequence_free( notif );
            }
        }
        else
        {
            rMutex_unlock( g_mutex );
        }
    }
}

static
RVOID
    processNewProcesses
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPWCHAR nameW = NULL;
    RPCHAR nameA = NULL;
    CryptoLib_Hash fileHash = { 0 };
    RU64 size = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW ) )
        {
            if( ( NULL != nameA &&
                  _MAX_FILE_HASH_SIZE < rpal_file_getSize( nameA, TRUE ) ) ||
                ( NULL != nameW &&
                  _MAX_FILE_HASH_SIZE < rpal_file_getSizew( nameW, TRUE ) ) )
            {
                rSequence_unTaintRead( event );
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_FILE_TOO_LARGE );
                rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA );
                rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW );
            }
            else
            {
                if( NULL != nameA &&
                    !CryptoLib_hashFileA( nameA, &fileHash, TRUE ) )
                {
                    rpal_debug_info( "unable to fetch file hash for ident" );
                }

                if( NULL != nameW &&
                    !CryptoLib_hashFileW( nameW, &fileHash, TRUE ) )
                {
                    rpal_debug_info( "unable to fetch file hash for ident" );
                }
            }
            
            rSequence_getRU64( event, RP_TAGS_MEMORY_SIZE, &size );

            if( NULL != nameA )
            {
                processCodeIdentA( nameA, &fileHash, size, event );
            }
            else if( NULL != nameW )
            {
                processCodeIdentW( nameW, &fileHash, size, event );
            }
        }
    }
}


static
RVOID
    processNewModule
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPWCHAR nameW = NULL;
    RPCHAR nameA = NULL;
    CryptoLib_Hash fileHash = { 0 };
    RU64 size = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW ) )
        {
            if( ( NULL != nameA &&
                _MAX_FILE_HASH_SIZE < rpal_file_getSize( nameA, TRUE ) ) ||
                ( NULL != nameW &&
                _MAX_FILE_HASH_SIZE < rpal_file_getSizew( nameW, TRUE ) ) )
            {
                // We already read from the event, but we will be careful.
                rSequence_unTaintRead( event );
                rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_FILE_TOO_LARGE );

                // We need to re-get the paths in case adding the error triggered
                // a change in the structure.
                rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA );
                rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW );
            }
            else
            {
                if( NULL != nameA &&
                    !CryptoLib_hashFileA( nameA, &fileHash, TRUE ) )
                {
                    rpal_debug_info( "unable to fetch file hash for ident" );
                }

                if( NULL != nameW &&
                    !CryptoLib_hashFileW( nameW, &fileHash, TRUE ) )
                {
                    rpal_debug_info( "unable to fetch file hash for ident" );
                }
            }

            rSequence_getRU64( event, RP_TAGS_MEMORY_SIZE, &size );

            if( NULL != nameA )
            {
                processCodeIdentA( nameA, &fileHash, size, event );
            }
            else if( NULL != nameW )
            {
                processCodeIdentW( nameW, &fileHash, size, event );
            }
        }
    }
}


static
RVOID
    processHashedEvent
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    RPWCHAR nameW = NULL;
    RPCHAR nameA = NULL;
    CryptoLib_Hash* pHash = NULL;
    CryptoLib_Hash localHash = { 0 };
    
    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW ) ||
            rSequence_getSTRINGA( event, RP_TAGS_DLL, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_DLL, &nameW ) ||
            rSequence_getSTRINGA( event, RP_TAGS_EXECUTABLE, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_EXECUTABLE, &nameW ) )
        {
            rSequence_getBUFFER( event, RP_TAGS_HASH, (RPU8*)&pHash, NULL );
            
            if( NULL != nameA )
            {
                if( NULL == pHash )
                {
                    if( _MAX_FILE_HASH_SIZE < rpal_file_getSize( nameA, TRUE ) )
                    {
                        rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_FILE_TOO_LARGE );
                    }
                    else if( CryptoLib_hashFileA( nameA, &localHash, TRUE ) )
                    {
                        pHash = &localHash;
                    }
                }

                processCodeIdentA( nameA, pHash, 0, event );
            }
            else if( NULL != nameW )
            {
                if( NULL == pHash )
                {
                    if( _MAX_FILE_HASH_SIZE < rpal_file_getSizew( nameW, TRUE ) )
                    {
                        rSequence_addRU32( event, RP_TAGS_ERROR, RPAL_ERROR_FILE_TOO_LARGE );
                    }
                    else if( CryptoLib_hashFileW( nameW, &localHash, TRUE ) )
                    {
                        pHash = &localHash;
                    }
                }

                processCodeIdentW( nameW, pHash, 0, event );
            }
        }
    }
}

static
RVOID
    processGenericSnapshot
    (
        rpcm_tag notifType,
        rSequence event
    )
{
    rList entityList = NULL;
    rSequence entity = NULL;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getLIST( event, RP_TAGS_AUTORUNS, &entityList ) ||
            rSequence_getLIST( event, RP_TAGS_SVCS, &entityList ) ||
            rSequence_getLIST( event, RP_TAGS_PROCESSES, &entityList ) )
        {
            // Go through the elements, whatever tag
            while( rList_getSEQUENCE( entityList, RPCM_INVALID_TAG, &entity ) )
            {
                processHashedEvent( notifType, entity );
            }
        }
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_3_events[] = { RP_TAGS_NOTIFICATION_CODE_IDENTITY,
                                  0 };

RBOOL
    collector_3_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;
    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( NULL != ( g_mutex = rMutex_create() ) )
        {
            if( NULL != ( g_knownCode = rpal_bloom_create( 50000, 0.00001 ) ) )
            {
                isSuccess = FALSE;

                if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, 0, NULL, processNewProcesses ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, 0, NULL, processNewModule ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, 0, NULL, processHashedEvent ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, 0, NULL, processGenericSnapshot ) &&
                    notifications_subscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, 0, NULL, processGenericSnapshot ) )
                {
                    isSuccess = TRUE;
                }
                else
                {
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, processHashedEvent );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, processGenericSnapshot );
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, processGenericSnapshot );
                    rpal_bloom_destroy( g_knownCode );
                    rMutex_free( g_mutex );
                    g_mutex = NULL;
                }
            }
            else
            {
                rMutex_free( g_mutex );
                g_mutex = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_3_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, NULL, processNewProcesses ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_SERVICE_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_DRIVER_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_AUTORUN_CHANGE, NULL, processHashedEvent ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_SERVICES_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_DRIVERS_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_PROCESSES_REP, NULL, processGenericSnapshot ) &&
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_OS_AUTORUNS_REP, NULL, processGenericSnapshot ) )
        {
            isSuccess = TRUE;
        }

        rpal_bloom_destroy( g_knownCode );
        g_knownCode = NULL;

        rMutex_free( g_mutex );
        g_mutex = NULL;
    }

    return isSuccess;
}

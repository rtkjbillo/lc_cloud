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

typedef struct
{
    RU8 nameHash[ CRYPTOLIB_HASH_SIZE ];
    RU8 fileHash[ CRYPTOLIB_HASH_SIZE ];
    RU64 codeSize;

} CodeIdent;

static rBloom g_knownCode = NULL;
static rMutex g_mutex = NULL;


static
RVOID
    processCodeIdentW
    (
        RPWCHAR name,
        RPU8 pFileHash,
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
    
    ident.codeSize = codeSize;

    if( NULL != name )
    {
        CryptoLib_hash( name, rpal_string_strlenw( name ) * sizeof( RWCHAR ), ident.nameHash );
    }

    if( NULL != pFileHash )
    {
        rpal_memory_memcpy( ident.fileHash, pFileHash, CRYPTOLIB_HASH_SIZE );
    }

    if( rMutex_lock( g_mutex ) )
    {
        if( rpal_bloom_addIfNew( g_knownCode, &ident, sizeof( ident ) ) )
        {
            rMutex_unlock( g_mutex );

            if( NULL != ( notif = rSequence_new() ) )
            {
                hbs_markAsRelated( originalEvent, notif );

                if( rSequence_addSTRINGW( notif, RP_TAGS_FILE_PATH, name ) &&
                    rSequence_addRU32( notif, RP_TAGS_MEMORY_SIZE, (RU32)codeSize ) &&
                    rSequence_addTIMESTAMP( notif, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() ) )
                {
                    if( NULL != pFileHash )
                    {
                        rSequence_addBUFFER( notif, RP_TAGS_HASH, pFileHash, CRYPTOLIB_HASH_SIZE );
                    }

                    if( libOs_getSignature( name,
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
        RPU8 pFileHash,
        RU64 codeSize,
        rSequence originalEvent
    )
{
    CodeIdent ident = { 0 };
    rSequence notif = NULL;
    rSequence sig = NULL;
    RPWCHAR wPath = NULL;

    ident.codeSize = codeSize;

    if( NULL != name )
    {
        CryptoLib_hash( name, rpal_string_strlen( name ) * sizeof( RCHAR ), ident.nameHash );
    }

    if( NULL != pFileHash )
    {
        rpal_memory_memcpy( ident.fileHash, pFileHash, CRYPTOLIB_HASH_SIZE );
    }

    if( rMutex_lock( g_mutex ) )
    {
        if( rpal_bloom_addIfNew( g_knownCode, &ident, sizeof( ident ) ) )
        {
            rMutex_unlock( g_mutex );

            if( NULL != ( notif = rSequence_new() ) )
            {
                hbs_markAsRelated( originalEvent, notif );

                if( rSequence_addSTRINGA( notif, RP_TAGS_FILE_NAME, name ) &&
                    rSequence_addRU32( notif, RP_TAGS_MEMORY_SIZE, (RU32)codeSize ) &&
                    rSequence_addTIMESTAMP( notif, RP_TAGS_TIMESTAMP, rpal_time_getGlobal() ) )
                {
                    if( NULL != pFileHash )
                    {
                        rSequence_addBUFFER( notif, RP_TAGS_HASH, pFileHash, CRYPTOLIB_HASH_SIZE );
                    }

                    if( NULL != ( wPath = rpal_string_atow( name ) ) )
                    {
                        if( libOs_getSignature( wPath, &sig, OSLIB_SIGNCHECK_NO_NETWORK, NULL, NULL, NULL ) )
                        {
                            if( !rSequence_addSEQUENCE( notif, RP_TAGS_SIGNATURE, sig ) )
                            {
                                rSequence_free( sig );
                            }
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
    RU8 fileHash[ CRYPTOLIB_HASH_SIZE ] = { 0 };
    RU64 size = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW ) )
        {
            if( NULL != nameA &&
                !CryptoLib_hashFileA( nameA, fileHash, TRUE ) )
            {
                rpal_debug_info( "unable to fetch file hash for ident" );
            }
            
            if( NULL != nameW &&
                !CryptoLib_hashFileW( nameW, fileHash, TRUE ) )
            {
                rpal_debug_info( "unable to fetch file hash for ident" );
            }

            rSequence_getRU64( event, RP_TAGS_MEMORY_SIZE, &size );

            if( NULL != nameA )
            {
                processCodeIdentA( nameA, fileHash, size, event );
            }
            else if( NULL != nameW )
            {
                processCodeIdentW( nameW, fileHash, size, event );
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
    RU8 fileHash[ CRYPTOLIB_HASH_SIZE ] = { 0 };
    RU64 size = 0;

    UNREFERENCED_PARAMETER( notifType );

    if( rpal_memory_isValid( event ) )
    {
        if( rSequence_getSTRINGA( event, RP_TAGS_FILE_PATH, &nameA ) ||
            rSequence_getSTRINGW( event, RP_TAGS_FILE_PATH, &nameW ) )
        {
            if( NULL != nameA &&
                !CryptoLib_hashFileA( nameA, fileHash, TRUE ) )
            {
                rpal_debug_info( "unable to fetch file hash for ident" );
            }

            if( NULL != nameW &&
                !CryptoLib_hashFileW( nameW, fileHash, TRUE ) )
            {
                rpal_debug_info( "unable to fetch file hash for ident" );
            }

            rSequence_getRU64( event, RP_TAGS_MEMORY_SIZE, &size );

            if( NULL != nameA )
            {
                processCodeIdentA( nameA, fileHash, size, event );
            }
            else if( NULL != nameW )
            {
                processCodeIdentW( nameW, fileHash, size, event );
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
                    notifications_subscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, 0, NULL, processNewModule ) )
                {
                    isSuccess = TRUE;
                }
                else
                {
                    notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule );
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
            notifications_unsubscribe( RP_TAGS_NOTIFICATION_MODULE_LOAD, NULL, processNewModule ) )
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

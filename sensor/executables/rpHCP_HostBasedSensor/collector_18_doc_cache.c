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
#include <cryptoLib/cryptoLib.h>

#define  RPAL_FILE_ID           102

#define MAX_CACHE_SIZE                  (1024 * 1024 * 50)
#define DOCUMENT_MAX_SIZE               (1024 * 1024 * 15)

static rQueue createQueue = NULL;
static HObs extensionMatcherA = NULL;
static HObs extensionMatcherW = NULL;

static HbsRingBuffer documentCache = NULL;
static RU32 cacheMaxSize = MAX_CACHE_SIZE;
static RU32 cacheSize = 0;
static rMutex cacheMutex = NULL;

typedef struct
{
    RPCHAR exprA;
    RPWCHAR exprW;
    CryptoLib_Hash* pHash;

} DocSearchContext;

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

static
RVOID
    processFile
    (
        rSequence notif
    )
{
    RPCHAR fileA = NULL;
    RPWCHAR fileW = NULL;
    RPU8 fileContent = NULL;
    RU32 fileSize = 0;
    CryptoLib_Hash hash = { 0 };

    if( NULL != notif )
    {
        if( ( rSequence_getSTRINGA( notif, RP_TAGS_FILE_PATH, &fileA ) &&
              obsLib_setTargetBuffer( extensionMatcherA, 
                                      fileA, 
                                      rpal_string_strlen( fileA ) + sizeof( RCHAR ) ) &&
              obsLib_nextHit( extensionMatcherA, NULL, NULL ) ) ||
            ( rSequence_getSTRINGW( notif, RP_TAGS_FILE_PATH, &fileW ) &&
              obsLib_setTargetBuffer( extensionMatcherW, 
                                      fileW, 
                                      rpal_string_strlenw( fileW ) + sizeof( RWCHAR ) ) &&
              obsLib_nextHit( extensionMatcherW, NULL, NULL ) ) )
        {
            // This means it's a file of interest.
            if( ( NULL != fileA &&
                  ( ( DOCUMENT_MAX_SIZE >= rpal_file_getSize( fileA, TRUE ) &&
                      rpal_file_read( fileA, &fileContent, &fileSize, TRUE ) &&
                      CryptoLib_hash( fileContent, fileSize, &hash ) ) ||
                    CryptoLib_hashFileA( fileA, &hash, TRUE ) ) ) ||
                ( NULL != fileW &&
                  ( ( DOCUMENT_MAX_SIZE >= rpal_file_getSizew( fileW, TRUE ) &&
                      rpal_file_readw( fileW, &fileContent, &fileSize, TRUE ) &&
                      CryptoLib_hash( fileContent, fileSize, &hash ) ) ||
                    CryptoLib_hashFileW( fileW, &hash, TRUE ) ) ) )
            {
                // We acquired the hash, either by reading the entire file in memory
                // which we will use for caching, or if it was too big by hashing it
                // sequentially on disk.
                rSequence_addBUFFER( notif, RP_TAGS_HASH, &hash, sizeof( hash ) );
                notifications_publish( RP_TAGS_NOTIFICATION_NEW_DOCUMENT, notif );
            }

            if( rMutex_lock( cacheMutex ) )
            {
                if( NULL == fileContent ||
                    !rSequence_addBUFFER( notif, RP_TAGS_FILE_CONTENT, fileContent, fileSize ) ||
                    !HbsRingBuffer_add( documentCache, notif ) )
                {
                    rSequence_free( notif );
                }

                rMutex_unlock( cacheMutex );
            }
        }
        else
        {
            rSequence_free( notif );
        }
    }
}

static
RPVOID
    parseDocuments
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence createEvt = NULL;
    
    UNREFERENCED_PARAMETER( ctx );

    while( rpal_memory_isValid( isTimeToStop ) &&
           !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( createQueue, &createEvt, NULL, MSEC_FROM_SEC( 1 ) ) )
        {
            processFile( createEvt );
        }
    }

    return NULL;
}

static
RBOOL
    findDoc
    (
        rSequence doc,
        DocSearchContext* ctx
    )
{
    RBOOL isMatch = FALSE;
    RPCHAR filePathA = NULL;
    RPWCHAR filePathW = NULL;
    CryptoLib_Hash* pHash = NULL;
    RU32 hashSize = 0;

    if( rpal_memory_isValid( doc ) &&
        NULL != ctx )
    {
        rSequence_getSTRINGA( doc, RP_TAGS_FILE_PATH, &filePathA );
        rSequence_getSTRINGW( doc, RP_TAGS_FILE_PATH, &filePathW );
        rSequence_getBUFFER( doc, RP_TAGS_HASH, &pHash, &hashSize );
    }

    return isMatch;
}

static
RVOID
    getDocument
    (
        rpcm_tag notifId,
        rSequence notif
    )
{
    RU32 i = 0;
    rSequence tmp = NULL;
    DocSearchContext ctx = { 0 };
    RU32 hashSize = 0;
    UNREFERENCED_PARAMETER( notifId );

    if( NULL != notif )
    {
        rSequence_getSTRINGA( notif, RP_TAGS_STRING_PATTERN, &ctx.exprA );
        rSequence_getSTRINGW( notif, RP_TAGS_STRING_PATTERN, &ctx.exprW );
        if( rSequence_getBUFFER( notif, RP_TAGS_HASH, &ctx.pHash, &hashSize ) &&
            sizeof( *ctx.pHash ) != hashSize )
        {
            // Unexpected hash size, let's not gamble
            ctx.pHash = NULL;
        }
    }

    if( rMutex_lock( cacheMutex ) )
    {
        

        rMutex_unlock( cacheMutex );
    }
}

//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_18_events[] = { RP_TAGS_NOTIFICATION_NEW_DOCUMENT,
                                   RP_TAGS_NOTIFICATION_GET_DOCUMENT_REP,
                                   0 };

RBOOL
    collector_18_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    rList extensions = NULL;
    RPCHAR extA = NULL;
    RPWCHAR extW = NULL;
    RU32 maxSize = 0;

    if( NULL != hbsState &&
        NULL != config )
    {
        if( rSequence_getLIST( config, RP_TAGS_EXTENSIONS, &extensions ) &&
            0 != rList_getNumElements( extensions ) )
        {
            if( NULL != ( cacheMutex = rMutex_create() ) &&
                NULL != ( extensionMatcherA = obsLib_new( 0, 0 ) ) &&
                NULL != ( extensionMatcherW = obsLib_new( 0, 0 ) ) )
            {
                cacheSize = 0;
                if( rSequence_getRU32( config, RP_TAGS_MAX_SIZE, &maxSize ) )
                {
                    cacheMaxSize = maxSize;
                }
                else
                {
                    cacheMaxSize = MAX_CACHE_SIZE;
                }
                
                if( NULL != ( documentCache = HbsRingBuffer_new( 0, cacheMaxSize ) ) )
                {
                    while( rList_getSTRINGA( extensions, RP_TAGS_EXTENSION, &extA ) )
                    {
                        obsLib_addPattern( extensionMatcherA,
                            extA,
                            rpal_string_strlen( extA ) + sizeof( RCHAR ),
                            NULL );
                    }

                    while( rList_getSTRINGW( extensions, RP_TAGS_EXTENSION, &extW ) )
                    {
                        obsLib_addPattern( extensionMatcherW,
                            extW,
                            rpal_string_strlenw( extW ) + sizeof( RWCHAR ),
                            NULL );
                    }

                    if( rQueue_create( &createQueue, _freeEvt, 200 ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, NULL, 0, createQueue, NULL ) &&
                        notifications_subscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, 0, NULL, getDocument ) &&
                        rThreadPool_task( hbsState->hThreadPool, parseDocuments, NULL ) )
                    {
                        isSuccess = TRUE;
                    }
                }
            }

            if( !isSuccess )
            {
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, createQueue, NULL );
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, getDocument );
                rQueue_free( createQueue );
                createQueue = NULL;

                obsLib_free( extensionMatcherA );
                obsLib_free( extensionMatcherW );
                HbsRingBuffer_free( documentCache );
                extensionMatcherA = NULL;
                extensionMatcherW = NULL;
                documentCache = NULL;

                rMutex_free( cacheMutex );
                cacheMutex = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_18_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_FILE_CREATE, createQueue, NULL );
        notifications_unsubscribe( RP_TAGS_NOTIFICATION_GET_DOCUMENT_REQ, NULL, getDocument );
        rQueue_free( createQueue );
        createQueue = NULL;

        obsLib_free( extensionMatcherA );
        obsLib_free( extensionMatcherW );
        HbsRingBuffer_free( documentCache );
        extensionMatcherA = NULL;
        extensionMatcherW = NULL;
        documentCache = NULL;

        rMutex_free( cacheMutex );
        cacheMutex = NULL;

        isSuccess = TRUE;
    }

    return isSuccess;
}

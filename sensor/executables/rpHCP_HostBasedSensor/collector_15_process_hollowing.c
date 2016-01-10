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


#define RPAL_FILE_ID                  97

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include "collectors.h"
#include <notificationsLib/notificationsLib.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include <processLib/processLib.h>
#include <obsLib/obsLib.h>

#define _SCRATCH_SIZE                   (1024*1024)
#define _MIN_DISK_SAMPLE_SIZE           30
#define _MAX_DISK_SAMPLE_SIZE           2000
#define _MIN_SAMPLE_STR_LEN             6
#define _MAX_SAMPLE_STR_LEN             40
#define _MAX_SAMPLE_SPECIAL_CHAR        0
#define _MIN_SAMPLE_MATCH_PERCENT       80

#define _CHECK_SEC_AFTER_PROCESS_CREATION   5
#define _CHECK_RANDOM_PROCESS_EVERY         (60*60)

static rQueue g_newProcessNotifications = NULL;



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
RBOOL
    _longestString
    (
        RPCHAR begin,
        RU32 max,
        RU32* toSkip,
        RU32* longestLength,
        RBOOL* isUnicode
    )
{
    RBOOL isSuccess = FALSE;
    RU32 size = 0;
    RWCHAR unicodeLow = 0xFF;
    RWCHAR unicodeHigh = ( (RWCHAR)( -1 ) ^ 0xFF );
    RPWCHAR possibleChar = NULL;
    RU32 nSpecialChar = 0;

    if( NULL != begin &&
        NULL != toSkip &&
        NULL != longestLength &&
        NULL != isUnicode )
    {
        *longestLength = 0;
        *toSkip = 0;

        for( size = 0; size < max; size++ )
        {
            if( 0 == begin[ size ] )
            {
                break;
            }
            else if( !rpal_string_charIsAscii( begin[ size ] ) ||
                     size == max - 1 )
            {
                // We're only looking for clean C NULL-terminated strings
                *toSkip = size + 1;
                return FALSE;
            }
            else if( rpal_string_charIsAscii( begin[ size ] ) &&
                     !rpal_string_charIsAlphaNum( begin[ size ] ) )
            {
                nSpecialChar++;
                if( nSpecialChar > _MAX_SAMPLE_SPECIAL_CHAR )
                {
                    // Too many special characters, may be binary data
                    *toSkip = size + 1;
                    return FALSE;
                }
            }
        }

        if( 1 == size )
        {
            // This looks like it might be the first character of a unicode
            // string. So let's look for one.
            *isUnicode = TRUE;

            for( size = 0; size < max; size += sizeof( RWCHAR ) )
            {
                possibleChar = (RPWCHAR)( begin + size );

                if( 0 == *possibleChar )
                {
                    break;
                }
                else
                {
                    if( !rpal_string_charIsAscii( (RCHAR)( *possibleChar & unicodeLow ) ) ||
                        0 != ( *possibleChar & unicodeHigh ) ||
                        size == max - sizeof( RWCHAR ) )
                    {
                        *toSkip = size + 1;
                        return FALSE;
                    }
                }
            }
        }

        *longestLength = size + 1;
        *toSkip = *longestLength;
        isSuccess = TRUE;
    }

    return isSuccess;
}

static
HObs
    _getModuleDiskStringSample
    (
        RPWCHAR modulePath
    )
{
    HObs sample = NULL;
    RPU8 scratch = NULL;
    rFile hFile = NULL;
    RU32 read = 0;
    RPU8 start = NULL;
    RPU8 end = NULL;
    RU32 toSkip = 0;
    RU32 longestLength = 0;
    RBOOL isUnicode = FALSE;
    RPU8 sampleNumber = 0;
    rBloom stringsSeen = NULL;

    if( NULL != modulePath )
    {
        if( NULL != ( stringsSeen = rpal_bloom_create( _MAX_DISK_SAMPLE_SIZE, 0.0001 ) ) )
        {
            if( NULL != ( sample = obsLib_new( _MAX_DISK_SAMPLE_SIZE, 0 ) ) )
            {
                if( NULL != ( scratch = rpal_memory_alloc( _SCRATCH_SIZE ) ) )
                {
                    if( rFile_open( modulePath, &hFile, RPAL_FILE_OPEN_EXISTING |
                        RPAL_FILE_OPEN_READ ) )
                    {
                        while( 0 != ( read = rFile_readUpTo( hFile, _SCRATCH_SIZE, scratch ) ) )
                        {
                            start = scratch;
                            end = scratch + read;

                            // We parse for strings up to 'read', we don't care about the 
                            // memory boundary, we might truncate some strings but we're
                            // sampling anyway.
                            while( ( start >= scratch ) && ( start >= scratch ) &&
                                ( start + _MIN_SAMPLE_STR_LEN ) < ( scratch + read ) &&
                                _MAX_DISK_SAMPLE_SIZE >= PTR_TO_NUMBER( sampleNumber ) )
                            {
                                isUnicode = FALSE;

                                if( _longestString( (RPCHAR)start,
                                    (RU32)( end - start ),
                                    &toSkip,
                                    &longestLength,
                                    &isUnicode ) &&
                                    _MIN_SAMPLE_STR_LEN <= longestLength &&
                                    _MAX_SAMPLE_STR_LEN >= longestLength )
                                {
                                    if( rpal_bloom_addIfNew( stringsSeen, start, longestLength ) )
                                    {
                                        /*
                                        if( isUnicode )
                                        {
                                            rpal_debug_info( "adding U: %ls", start );
                                        }
                                        else
                                        {
                                            rpal_debug_info( "adding: %s", start );
                                        }
                                        */

                                        if( obsLib_addPattern( sample, start, longestLength, sampleNumber ) )
                                        {
                                            sampleNumber++;
                                        }
                                    }
                                    else
                                    {
                                        /*
                                        if( isUnicode )
                                        {
                                            rpal_debug_info( "duplicate U: %ls", start );
                                        }
                                        else
                                        {
                                            rpal_debug_info( "duplicate: %s", start );
                                        }
                                        */
                                    }
                                }

                                start += toSkip;
                            }
                        }

                        rFile_close( hFile );
                    }

                    rpal_memory_free( scratch );
                }
            }

            rpal_bloom_destroy( stringsSeen );
        }
    }

    return sample;
}

static
RBOOL
    _checkMemoryForStringSample
    (
        HObs sample,
        RU32 pid,
        RPVOID moduleBase,
        RU64 moduleSize
    )
{
    RBOOL isHollowed = FALSE;

    RPU8 pMem = NULL;
    RU8* sampleList = NULL;
    RPU8 sampleNumber = 0;
    RU32 nSamples = 0;
    RU32 nSamplesFound = 0;

    if( NULL != sample &&
        0 != pid &&
        NULL != moduleBase &&
        0 != moduleSize &&
        _MIN_DISK_SAMPLE_SIZE <= ( nSamples = obsLib_getNumPatterns( sample ) ) )
    {
        if( NULL != ( sampleList = rpal_memory_alloc( sizeof( RU8 ) * nSamples ) ) )
        {
            rpal_memory_zero( sampleList, sizeof( RU8 ) * nSamples );

            if( processLib_getProcessMemory( pid, moduleBase, moduleSize, (RPVOID*)&pMem, TRUE ) )
            {
                if( obsLib_setTargetBuffer( sample, pMem, (RU32)moduleSize ) )
                {
                    while( obsLib_nextHit( sample, (RPVOID*)&sampleNumber, NULL ) )
                    {
                        if( sampleNumber < (RPU8)NUMBER_TO_PTR( nSamples ) &&
                            0 == sampleList[ (RU32)PTR_TO_NUMBER( sampleNumber ) ] )
                        {
                            sampleList[ (RU32)PTR_TO_NUMBER( sampleNumber ) ] = 1;
                            nSamplesFound++;
                        }
                    }

                    rpal_debug_info( "process hollowing check found a match of %d / %d", nSamplesFound, nSamples );
                    if( ( ( (RFLOAT)nSamplesFound / nSamples ) * 100 ) < _MIN_SAMPLE_MATCH_PERCENT )
                    {
                        isHollowed = TRUE;
                    }
                }

                rpal_memory_free( pMem );
            }
            else
            {
                rpal_debug_info( "failed to get memory for %d: 0x%016X ( 0x%016X ) error %d", 
                                 pid, 
                                 moduleBase, 
                                 moduleSize,
                                 rpal_error_getLast() );
            }

            rpal_memory_free( sampleList );
        }
    }

    return isHollowed;
}

static
rList
    _spotCheckProcess
    (
        rEvent isTimeToStop,
        RU32 pid
    )
{
    rList hollowedModules = NULL;

    rList modules = NULL;
    rSequence module = NULL;
    RPWCHAR modulePathW = NULL;
    RPCHAR modulePathA = NULL;
    RU64 moduleBase = 0;
    RU64 moduleSize = 0;
    HObs diskSample = NULL;
    rSequence hollowedModule = NULL;

    rpal_debug_info( "spot checking process %d", pid );

    if( NULL != ( modules = processLib_getProcessModules( pid ) ) )
    {
        while( !rEvent_wait( isTimeToStop, 0 ) &&
               rList_getSEQUENCE( modules, RP_TAGS_DLL, &module ) )
        {
            modulePathW = NULL;
            modulePathA = NULL;
            
            if( ( rSequence_getSTRINGW( module, 
                                        RP_TAGS_FILE_PATH, 
                                        &modulePathW ) ||
                  rSequence_getSTRINGA( module,
                                        RP_TAGS_FILE_PATH,
                                        &modulePathA ) ) &&
                rSequence_getPOINTER64( module, RP_TAGS_BASE_ADDRESS, &moduleBase ) &&
                rSequence_getRU64( module, RP_TAGS_MEMORY_SIZE, &moduleSize ) )
            {
                if( NULL != modulePathA && 
                    NULL == modulePathW )
                {
                    modulePathW = rpal_string_atow( modulePathA );
                }

                if( NULL != modulePathW )
                {
                    //rpal_debug_info( "checking module %ls", modulePathW );
                    if( NULL != ( diskSample = _getModuleDiskStringSample( modulePathW ) ) )
                    {
                        if( _checkMemoryForStringSample( diskSample,
                                                         pid,
                                                         NUMBER_TO_PTR( moduleBase ),
                                                         moduleSize ) )
                        {
                            //rpal_debug_info( "sign of process hollowing found in process %d module %ls",
                                             //pid,
                                             //modulePathW );
                            if( NULL != ( hollowedModule = rSequence_duplicate( module ) ) )
                            {
                                if( !rList_addSEQUENCE( hollowedModules, hollowedModule ) )
                                {
                                    rSequence_free( hollowedModule );
                                }
                            }
                        }

                        obsLib_free( diskSample );
                    }
                }

                if( NULL != modulePathA &&
                    NULL != modulePathW )
                {
                    rpal_memory_free( modulePathW );
                }
            }
            else
            {
                rpal_debug_info( "module missing characteristic" );
            }
        }

        rList_free( modules );
    }
    else
    {
        rpal_debug_info( "failed to get process modules, might be dead" );
    }

    return hollowedModules;
}

static
RPVOID
    spotCheckAllProcesses
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    rList hollowedModules = NULL;
    rSequence processInfo = NULL;

    if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
    {
        proc = procs;

        while( 0 != proc->pid &&
            rpal_memory_isValid( isTimeToStop ) &&
            !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
        {
            if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, proc->pid ) ) )
            {
                if( NULL != ( processInfo = processLib_getProcessInfo( proc->pid ) ) ||
                    ( NULL != ( processInfo = rSequence_new() ) &&
                      rSequence_addRU32( processInfo, RP_TAGS_PROCESS_ID, proc->pid ) ) )
                {
                    if( !rSequence_addLIST( processInfo, RP_TAGS_MODULES, hollowedModules ) )
                    {
                        rList_free( hollowedModules );
                    }
                    else
                    {
                        hbs_markAsRelated( originalRequest, processInfo );
                        notifications_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, processInfo );
                    }

                    rSequence_free( processInfo );
                }
                else
                {
                    rList_free( hollowedModules );
                }
            }
            proc++;
        }

        rpal_memory_free( procs );
    }

    return NULL;
}

static
RPVOID
    spotCheckRandomProcess
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    rSequence originalRequest = (rSequence)ctx;
    processLibProcEntry* procs = NULL;
    processLibProcEntry* proc = NULL;
    rList hollowedModules = NULL;
    rSequence processInfo = NULL;
    RU32 nProcesses = 0;
    RU32 pid = 0;

    rpal_debug_info( "spot checking random process" );

    if( NULL != ( procs = processLib_getProcessEntries( TRUE ) ) )
    {
        proc = procs;
        while( 0 != proc->pid )
        {
            nProcesses++;
            proc++;
        }

        if( 0 != nProcesses )
        {
            pid = ( procs + ( rpal_rand() % nProcesses ) )->pid;
        }

        rpal_memory_free( procs );
    }

    if( 0 != pid &&
        rpal_memory_isValid( isTimeToStop ) &&
        !rEvent_wait( isTimeToStop, MSEC_FROM_SEC( 5 ) ) )
    {
        if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, pid ) ) )
        {
            if( NULL != ( processInfo = processLib_getProcessInfo( pid ) ) ||
                ( NULL != ( processInfo = rSequence_new() ) &&
                rSequence_addRU32( processInfo, RP_TAGS_PROCESS_ID, pid ) ) )
            {
                if( !rSequence_addLIST( processInfo, RP_TAGS_MODULES, hollowedModules ) )
                {
                    rList_free( hollowedModules );
                }
                else
                {
                    hbs_markAsRelated( originalRequest, processInfo );
                    notifications_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, processInfo );
                }

                rSequence_free( processInfo );
            }
            else
            {
                rList_free( hollowedModules );
            }
        }
    }

    return NULL;
}

static
RPVOID
    spotCheckNewProcesses
    (
        rEvent isTimeToStop,
        RPVOID ctx
    )
{
    RU32 pid = 0;
    RTIME timestamp = 0;
    RTIME timeToWait = 0;
    RTIME now = 0;
    rSequence newProcess = NULL;
    rList hollowedModules = NULL;

    UNREFERENCED_PARAMETER( ctx );

    while( !rEvent_wait( isTimeToStop, 0 ) )
    {
        if( rQueue_remove( g_newProcessNotifications, &newProcess, NULL, MSEC_FROM_SEC( 5 ) ) )
        {
            if( rSequence_getRU32( newProcess, RP_TAGS_PROCESS_ID, &pid ) &&
                rSequence_getTIMESTAMP( newProcess, RP_TAGS_TIMESTAMP, &timestamp ) )
            {
                timeToWait = timestamp + _CHECK_SEC_AFTER_PROCESS_CREATION;
                now = rpal_time_getGlobal();
                if( now < timeToWait )
                {
                    rpal_thread_sleep( (RU32)MSEC_FROM_SEC( timeToWait - now ) );
                }

                if( NULL != ( hollowedModules = _spotCheckProcess( isTimeToStop, pid ) ) )
                {
                    if( !rSequence_addLIST( newProcess, RP_TAGS_MODULES, hollowedModules ) )
                    {
                        rList_free( hollowedModules );
                    }
                    else
                    {
                        notifications_publish( RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH, 
                                               newProcess );
                    }
                }
            }

            rSequence_free( newProcess );
        }
    }

    return NULL;
}


//=============================================================================
// COLLECTOR INTERFACE
//=============================================================================

rpcm_tag collector_15_events[] = { RP_TAGS_NOTIFICATION_MODULE_MEM_DISK_MISMATCH,
                                   0 };

RBOOL
    collector_15_init
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( config );

    if( NULL != hbsState )
    {
        if( rQueue_create( &g_newProcessNotifications, _freeEvt, 20 ) )
        {
            if( notifications_subscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                         NULL, 
                                         0, 
                                         g_newProcessNotifications, 
                                         NULL ) &&
                rThreadPool_scheduleRecurring( hbsState->hThreadPool, 
                                               _CHECK_RANDOM_PROCESS_EVERY, 
                                               spotCheckRandomProcess, 
                                               NULL, 
                                               TRUE ) &&
                rThreadPool_task( hbsState->hThreadPool, spotCheckNewProcesses, NULL ) )
            {
                isSuccess = TRUE;
            }
            else
            {
                notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                           g_newProcessNotifications, 
                                           NULL );
                rQueue_free( g_newProcessNotifications );
                g_newProcessNotifications = NULL;
            }
        }
    }

    return isSuccess;
}

RBOOL
    collector_15_cleanup
    (
        HbsState* hbsState,
        rSequence config
    )
{
    RBOOL isSuccess = FALSE;

    UNREFERENCED_PARAMETER( hbsState );
    UNREFERENCED_PARAMETER( config );

    if( notifications_unsubscribe( RP_TAGS_NOTIFICATION_NEW_PROCESS, 
                                   g_newProcessNotifications, 
                                   NULL ) )
    {
        if( rQueue_free( g_newProcessNotifications ) )
        {
            isSuccess = TRUE;
            g_newProcessNotifications = NULL;
        }
    }

    return isSuccess;
}

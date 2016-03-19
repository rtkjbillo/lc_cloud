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


#define _NUM_BUFFERED_FILES 200

static rMutex g_collector_2_mutex = NULL;
static KernelAcqFileIo g_files[ _NUM_BUFFERED_FILES ] = { 0 };
static uint32_t g_nextFile = 0;

#include <sys/kauth.h>

static kauth_listener_t g_listener = NULL;

static void
    next_file
    (

    )
{
    g_nextFile++;
    if( g_nextFile == _NUM_BUFFERED_FILES )
    {
        g_nextFile = 0;
        rpal_debug_warning( "overflow of the file io buffer" );
    }
}

static int
    new_file_listener
    (
        kauth_cred_t   credential,
        void *         idata,
        kauth_action_t action,
        uintptr_t      arg0,
        uintptr_t      arg1,
        uintptr_t      arg2,
        uintptr_t      arg3
    )
{
    char* file_path = NULL;
    int file_action = 0;
    
    pid_t pid = 0;
    uid_t uid = 0;
    uint64_t ts = 0;
    
    if( KAUTH_FILEOP_OPEN != action &&
        KAUTH_FILEOP_RENAME != action &&
        KAUTH_FILEOP_EXEC != action &&
        KAUTH_FILEOP_DELETE != action )
    {
        return KAUTH_RESULT_DEFER;
    }
    
    uid = kauth_getuid();
    pid = proc_selfpid();
    ts = rpal_time_getLocal();
    
    rpal_mutex_lock( g_collector_2_mutex );
    
    g_files[ g_nextFile ].pid = pid;
    g_files[ g_nextFile ].uid = uid;
    g_files[ g_nextFile ].ts = ts;
    
    switch( action )
    {
        case KAUTH_FILEOP_OPEN:
            file_action = KERNEL_ACQ_FILE_ACTION_MODIFIED;
            file_path = (char*)arg1;
            strncpy( g_files[ g_nextFile ].path,
                     file_path,
                     sizeof( g_files[ g_nextFile ].path ) - 1 );
            rpal_debug_info( "FILEIO-OPEN: %lld %d %d %s", ts, uid, pid, file_path );
            break;
        case KAUTH_FILEOP_RENAME:
            file_action = KERNEL_ACQ_FILE_ACTION_RENAME_OLD;
            file_path = (char*)arg0;
            strncpy( g_files[ g_nextFile ].path,
                     file_path,
                     sizeof( g_files[ g_nextFile ].path ) - 1 );
            rpal_debug_info( "FILEIO-RENAME-OLD: %lld %d %d %s", ts, uid, pid, file_path );
            
            // We're generating two records so we increment manually
            next_file();
            
            g_files[ g_nextFile ].pid = pid;
            g_files[ g_nextFile ].uid = uid;
            g_files[ g_nextFile ].ts = ts;
            file_action = KERNEL_ACQ_FILE_ACTION_RENAME_NEW;
            file_path = (char*)arg1;
            strncpy( g_files[ g_nextFile ].path,
                     file_path,
                     sizeof( g_files[ g_nextFile ].path ) - 1 );
            rpal_debug_info( "FILEIO-RENAME-NEW: %lld %d %d %s", ts, uid, pid, file_path );
            break;
        case KAUTH_FILEOP_EXEC:
            file_action = KERNEL_ACQ_FILE_ACTION_MODIFIED;
            file_path = (char*)arg1;
            strncpy( g_files[ g_nextFile ].path,
                     file_path,
                     sizeof( g_files[ g_nextFile ].path ) - 1 );
            rpal_debug_info( "FILEIO-EXEC: %lld %d %d %s", ts, uid, pid, file_path );
            break;
        case KAUTH_FILEOP_DELETE:
            file_action = KERNEL_ACQ_FILE_ACTION_REMOVED;
            file_path = (char*)arg1;
            strncpy( g_files[ g_nextFile ].path,
                     file_path,
                     sizeof( g_files[ g_nextFile ].path ) - 1 );
            rpal_debug_info( "FILEIO-EXEC: %lld %d %d %s", ts, uid, pid, file_path );
            break;
        default:
            rpal_mutex_unlock( g_collector_2_mutex );
            return KAUTH_RESULT_DEFER;
    }
    
    next_file();
    
    rpal_mutex_unlock( g_collector_2_mutex );
    
    rpal_debug_info( "now %d fileio in buffer", g_nextFile );
    
    return KAUTH_RESULT_DEFER;
}

int
    task_get_new_fileio
    (
        void* pArgs,
        int argsSize,
        void* pResult,
        uint32_t* resultSize
    )
{
    int ret = 0;
    
    int toCopy = 0;
    
    if( NULL != pResult &&
       NULL != resultSize &&
       0 != *resultSize )
    {
        rpal_mutex_lock( g_collector_2_mutex );
        toCopy = (*resultSize) / sizeof( KernelAcqFileIo );
        
        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextFile ? g_nextFile : toCopy );
            
            *resultSize = toCopy * sizeof( KernelAcqFileIo );
            memcpy( pResult, g_files, *resultSize );
            
            g_nextFile -= toCopy;
            memmove( g_files, g_files + toCopy, g_nextFile );
        }
        
        rpal_mutex_unlock( g_collector_2_mutex );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
    collector_2_initialize
    (
        void* d
    )
{
    int isSuccess = 0;
    
    if( NULL != ( g_collector_2_mutex = rpal_mutex_create() ) )
    {
        g_listener = kauth_listen_scope( KAUTH_SCOPE_FILEOP, new_file_listener, NULL );
        if( NULL != g_listener )
        {
            isSuccess = 1;
        }

        if( !isSuccess )
        {
            rpal_mutex_free( g_collector_2_mutex );
        }
    }
    
    return isSuccess;
}

int
    collector_2_deinitialize
    (

    )
{
    rpal_mutex_lock( g_collector_2_mutex );
    kauth_unlisten_scope( g_listener );
    rpal_mutex_free( g_collector_2_mutex );
    return 1;
}
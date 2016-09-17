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
#include "helpers.h"
#include <kernelAcquisitionLib/common.h>
#include <fltKernel.h>

#define _NUM_BUFFERED_FILES 200

static KSPIN_LOCK g_collector_2_mutex = { 0 };
static KernelAcqFileIo g_files[ _NUM_BUFFERED_FILES ] = { 0 };
static RU32 g_nextFile = 0;
static PFLT_FILTER g_filter = NULL;

static
FLT_PREOP_CALLBACK_STATUS
    FileFilterPreCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS status = FLT_PREOP_SUCCESS_NO_CALLBACK;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    return status;
}

static
FLT_POSTOP_CALLBACK_STATUS
    FileFilterPostCallback
    (
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    )
{
    FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;

    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    return status;
}

static
NTSTATUS
    FileFilterUnload
    (
        FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );
    FltUnregisterFilter( g_filter );
    return STATUS_SUCCESS;
}

static
NTSTATUS
    FileFilterQueryTeardown
    (
        PCFLT_RELATED_OBJECTS FltObjects,
        FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    return STATUS_SUCCESS;
}

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg("INIT")
#pragma const_seg("INIT")
#endif

const FLT_OPERATION_REGISTRATION g_filterCallbacks[] = {
    { IRP_MJ_CREATE,
      0,
      FileFilterPreCallback,
      FileFilterPostCallback },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION g_filterContexts[] = {
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION g_filterRegistration = 
{
    sizeof( FLT_REGISTRATION ),             //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    0,                                      //  Flags
    g_filterContexts,                       //  Context
    g_filterCallbacks,                      //  Operation callbacks
    FileFilterUnload,                       //  FilterUnload
    NULL,                                   //  InstanceSetup
    FileFilterQueryTeardown,                //  InstanceQueryTeardown
    NULL,                                   //  InstanceTeardownStart
    NULL,                                   //  InstanceTeardownComplete
    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg()
#pragma const_seg()
#endif

RBOOL
    task_get_new_files
    (
        RPU8 pArgs,
        RU32 argsSize,
        RPU8 pResult,
        RU32* resultSize
    )
{
    RBOOL isSuccess = FALSE;
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    RU32 toCopy = 0;

    UNREFERENCED_PARAMETER( pArgs );
    UNREFERENCED_PARAMETER( argsSize );

    if( NULL != pResult &&
        NULL != resultSize &&
        0 != *resultSize )
    {
        KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );

        toCopy = ( *resultSize ) / sizeof( KernelAcqFileIo );

        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextFile ? g_nextFile : toCopy );

            *resultSize = toCopy * sizeof( KernelAcqFileIo );
            memcpy( pResult, g_files, *resultSize );

            g_nextFile -= toCopy;
            memmove( g_files, g_files + toCopy, g_nextFile );
        }

        KeReleaseInStackQueuedSpinLock( &hMutex );

        isSuccess = TRUE;
    }

    return isSuccess;
}

/*
static VOID
    CreateProcessNotifyEx
    (
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    KLOCK_QUEUE_HANDLE hMutex = { 0 };

    UNREFERENCED_PARAMETER( Process );

    KeAcquireInStackQueuedSpinLock( &g_collector_2_mutex, &hMutex );


    // We're only interested in starts for now, a non-NULL CreateInfo indicates this.
    if( NULL != CreateInfo )
    {
        g_files[ g_nextFile ].pid = (RU32)ProcessId;
        g_files[ g_nextFile ].ppid = (RU32)PsGetCurrentProcessId();
        g_files[ g_nextFile ].ts = rpal_time_getLocal();
        g_files[ g_nextFile ].uid = KERNEL_ACQ_NO_USER_ID;

        copyUnicodeStringToBuffer( CreateInfo->ImageFileName,
            g_files[ g_nextFile ].path );

        copyUnicodeStringToBuffer( CreateInfo->CommandLine,
            g_files[ g_nextFile ].cmdline );

        g_nextFile++;
        if( g_nextFile == _NUM_BUFFERED_FILES )
        {
            g_nextFile = 0;
        }
    }

    KeReleaseInStackQueuedSpinLock( &hMutex );
}
*/

RBOOL
    collector_2_initialize
    (
        PDRIVER_OBJECT driverObject
    )
{
    RBOOL isSuccess = FALSE;
    RU32 status = 0;

    KeInitializeSpinLock( &g_collector_2_mutex );

    status = FltRegisterFilter( driverObject, &g_filterRegistration, &g_filter );

    if( NT_SUCCESS( status ) )
    {
        status = FltStartFiltering( g_filter );
        if( NT_SUCCESS( status ) )
        {
            isSuccess = TRUE;
        }
        else
        {
            rpal_debug_kernel( "Failed to start: 0x%08X", status );
            FltUnregisterFilter( g_filter );
        }
    }
    else
    {
        rpal_debug_kernel( "Failed to initialize: 0x%08X", status );
    }

    return isSuccess;
}

RBOOL
    collector_2_deinitialize
    (

    )
{
    RBOOL isSuccess = FALSE;
    RU32 status = STATUS_SUCCESS;

    if( NT_SUCCESS( status ) )
    {
        isSuccess = TRUE;
    }
    else
    {
        rpal_debug_kernel( "Failed to deinitialize: 0x%08X", status );
    }

    return isSuccess;
}

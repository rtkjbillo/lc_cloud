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

#include <kernelAcquisitionLib/kernelAcquisitionLib.h>
#include <rpHostCommonPlatformLib/rTags.h>

#define RPAL_FILE_ID   101

rMutex g_km_mutex = NULL;
#define KERNEL_ACQUISITION_TIMEOUT      5

#ifdef RPAL_PLATFORM_MACOSX
    #include <sys/socket.h>
    #include <sys/select.h>
    #include <sys/time.h>
    #include <mach/mach_types.h>
    #include <sys/errno.h>
    #include <sys/kern_control.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
    #include <sys/sys_domain.h>

    static int g_km_socket = (-1);
#endif

static RBOOL g_is_available = FALSE;

static
RU32
    _krnlSendReceive
    (
        int op,
        KernelAcqCommand* cmd
    )
{
    RU32 error = (RU32)(-1);

    if( NULL != cmd &&
        rMutex_lock( g_km_mutex ) )
    {
#ifdef RPAL_PLATFORM_MACOSX
        fd_set readset = { 0 };
        struct timeval timeout = { 0 };
        int waitVal = 0;

        error = setsockopt( g_km_socket, SYSPROTO_CONTROL, op, cmd, sizeof( *cmd ) );
#else
        UNREFERENCED_PARAMETER( op );
#endif

        rMutex_unlock( g_km_mutex );
    }

    return error;
}


RBOOL
    kAcq_init
    (

    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_MACOSX
    int result = 0;
    struct ctl_info info = { 0 };
    struct sockaddr_ctl addr = { 0 };
    if( (-1) == g_km_socket )
    {
        g_is_available = FALSE;

        if( NULL != ( g_km_mutex = rMutex_create() ) )
        {
            if( (-1) != ( g_km_socket = socket( PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL ) ) )
            {
                strncpy( info.ctl_name, ACQUISITION_COMMS_NAME, sizeof(info.ctl_name) );
                if( 0 == ioctl( g_km_socket, CTLIOCGINFO, &info ) )
                {
                    addr.sc_id = info.ctl_id;
                    addr.sc_unit = 0;
                    addr.sc_len = sizeof( struct sockaddr_ctl );
                    addr.sc_family = AF_SYSTEM;
                    addr.ss_sysaddr = AF_SYS_CONTROL;
                    if( 0 == ( result = connect( g_km_socket, (struct sockaddr *)&addr, sizeof(addr) ) ) )
                    {
                        isSuccess = TRUE;
                    }
                }

                if( !isSuccess )
                {
                    close( g_km_socket );
                    g_km_socket = (-1);
                }
            }

            if( !isSuccess )
            {
                rMutex_free( g_km_mutex );
                g_km_mutex = NULL;
            }
        }
    }
    else
    {
        isSuccess = TRUE;
    }
#endif

    return isSuccess;
}

RBOOL
    kAcq_deinit
    (

    )
{
    RBOOL isSuccess = FALSE;

#ifdef RPAL_PLATFORM_MACOSX
    if( rMutex_lock( g_km_mutex ) )
    {
        if( (-1) != g_km_socket )
        {
            close( g_km_socket );
            g_km_socket = (-1);
            isSuccess = TRUE;
        }

        g_is_available = FALSE;

        rMutex_free( g_km_mutex );
        g_km_mutex = NULL;
    }
#endif

    return isSuccess;
}

RBOOL
    kAcq_ping
    (

    )
{
    RBOOL isAvailable = FALSE;
    KernelAcqCommand cmd = { 0 };
    RU32 error = 0;

    RU32 challenge = ACQUISITION_COMMS_CHALLENGE;
    RU32 response = 0;

    RU32 respSize = 0;

    cmd.pArgs = &challenge;
    cmd.argsSize = sizeof( challenge );
    cmd.pResult = &response;
    cmd.resultSize = sizeof( response );
    cmd.pSizeUsed = &respSize;

    if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_PING, &cmd ) ) &&
        sizeof( RU32 ) == respSize )
    {
        if( ACQUISITION_COMMS_RESPONSE == response )
        {
            isAvailable = TRUE;
            g_is_available = TRUE;
        }
        else
        {
            g_is_available = FALSE;
        }
    }
    else
    {
        g_is_available = FALSE;
    }

    return isAvailable;
}

RBOOL
    kAcq_isAvailable
    (

    )
{
    return g_is_available;
}

RBOOL
    kAcq_getNewProcesses
    (
        KernelAcqProcess* entries,
        RU32* nEntries
    )
{
    RBOOL isSuccess = FALSE;

    RU32 error = 0;
    KernelAcqCommand cmd = { 0 };
    RU32 respSize = 0;

    if( NULL != entries &&
        NULL != nEntries &&
        0 != *nEntries )
    {
        cmd.pArgs = NULL;
        cmd.argsSize = 0;
        cmd.pResult = entries;
        cmd.resultSize = *nEntries * sizeof( *entries );
        cmd.pSizeUsed = &respSize;

        if( 0 == ( error = _krnlSendReceive( KERNEL_ACQ_OP_GET_NEW_PROCESSES, &cmd ) ) )
        {
            *nEntries = respSize / sizeof( *entries );
            isSuccess = TRUE;
        }
    }

    return isSuccess;
}

#include <rpal/rpal.h>
#include <processLib/processLib.h>

#ifdef RPAL_PLATFORM_LINUX
#include <signal.h>
#endif

/*
 * This executable simulates a few different types of memory loading to be used to
 * test detection capabilities like Yara memory scanning.
 */

rEvent g_timeToQuit = NULL;

#ifdef RPAL_PLATFORM_WINDOWS
BOOL
    ctrlHandler
    (
        DWORD type
    )
{
    BOOL isHandled = FALSE;

    static RU32 isHasBeenSignaled = 0;

    UNREFERENCED_PARAMETER( type );

    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        // We handle all events the same way, cleanly exit

        rpal_debug_info( "terminating." );
        rEvent_set( g_timeToQuit );

        isHandled = TRUE;
    }

    return isHandled;
}
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
void
    ctrlHandler
    (
        int sigNum
    )
{
    static RU32 isHasBeenSignaled = 0;

    if( 0 == rInterlocked_set32( &isHasBeenSignaled, 1 ) )
    {
        rpal_debug_info( "terminating." );
        rEvent_set( g_timeToQuit );
    }
}
#endif

RVOID
    printUsage
    (

    )
{
    printf( "Usage: -m method -t target" );
    printf( "-m method: the loading method to use, one of" );
    printf( "\t1: simple loading, no mapping, not executable" );
    printf( "-t target: the target file to load in memory" );
}

int
RPAL_EXPORT
    main
    (
        int argc,
        char* argv[]
    )
{
    RU32 memUsed = 0;
    RCHAR argFlag = 0;
    RPCHAR argVal = NULL;

    rpal_opt switches[] = { { 't', "target", TRUE },
                            { 'm', "method", TRUE } };

    // Execution Environment
    RPCHAR target = NULL;
    RU32 method = 0;

    // Method-specific variables.
    RPU8 loadedBuffer = NULL;
    RU32 loadedSize = 0;

    rpal_debug_info( "initializing..." );
    if( rpal_initialize( NULL, 0 ) )
    {
        // Initialize boilerplate runtime.
        if( NULL == ( g_timeToQuit = rEvent_create( TRUE ) ) )
        {
            rpal_debug_critical( "Failed to create timeToQuit event." );
            return -1;
        }

#ifdef RPAL_PLATFORM_WINDOWS
        if( !SetConsoleCtrlHandler( (PHANDLER_ROUTINE)ctrlHandler, TRUE ) )
        {
            rpal_debug_error( "error registering control handler function." );
            return -1;
        }
#elif defined( RPAL_PLATFORM_LINUX ) || defined( RPAL_PLATFORM_MACOSX )
        if( SIG_ERR == signal( SIGINT, ctrlHandler ) )
        {
            rpal_debug_error( "error setting signal handler" );
            return -1;
        }
#endif

        // Parse arguments on the type of simulation requested.
        while( -1 != ( argFlag = rpal_getopt( argc, argv, switches, &argVal ) ) )
        {
            switch( argFlag )
            {
                case 't':
                    target = argVal;
                    break;
                case 'm':
                    if( rpal_string_atoi( argVal, &method ) )
                    {
                        break;
                    }
                default:
                    printUsage();
                    return -1;
            }
        }

        if( 0 == method ||
            NULL == target )
        {
            printUsage();
            return -1;
        }

        // Execute the loading as requested.
        switch( method )
        {
            // Method 1: simple load in memory of a buffer, no mapping, not executable.
            case 1:
                if( !rpal_file_read( target, (RPVOID*)&loadedBuffer, &loadedSize, FALSE ) )
                {
                    rpal_debug_error( "Failed to load target file in buffer." );
                }
                break;
        }

        rpal_debug_info( "Loading complete, waiting for signal to exit." );
        rEvent_wait( g_timeToQuit, RINFINITE );
        rEvent_free( g_timeToQuit );

        // Cleanup whatever is left in memory.
        rpal_memory_free( loadedBuffer );

        rpal_debug_info( "...exiting..." );
        rpal_Context_cleanup();

#ifdef RPAL_PLATFORM_DEBUG
        memUsed = rpal_memory_totalUsed();
        if( 0 != memUsed )
        {
            rpal_debug_critical( "Memory leak: %d bytes.\n", memUsed );
            rpal_memory_findMemory();
        }
#else
        UNREFERENCED_PARAMETER( memUsed );
#endif
        
        rpal_Context_deinitialize();
    }
    else
    {
        rpal_debug_error( "error initializing rpal." );
    }

    return 0;
}

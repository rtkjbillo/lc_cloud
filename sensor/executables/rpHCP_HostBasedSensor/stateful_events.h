#ifndef HBS_STATEFUL_DETECTS_H
#define HBS_STATEFUL_DETECTS_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <rpHostCommonPlatformLib/rTags.h>
#include "stateful_widgets.h"

//=============================================================================
// Stateful Detects Naming Convention
//=============================================================================
#define DECLARE_STATEFUL(num) StatefulWidget stateful_ ##num## _create();

#define ENABLED_STATEFUL(num,output_event) { TRUE, stateful_ ##num## _create, output_event }
#define DISABLED_STATEFUL(num,output_event) { FALSE, stateful_ ##num## _create, output_event }

#ifdef RPAL_PLATFORM_WINDOWS
#define ENABLED_WINDOWS_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define ENABLED_LINUX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define ENABLED_OSX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define DISABLED_WINDOWS_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define DISABLED_LINUX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define DISABLED_OSX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#elif defined( RPAL_PLATFORM_LINUX )
#define ENABLED_WINDOWS_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define ENABLED_LINUX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define ENABLED_OSX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define DISABLED_WINDOWS_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define DISABLED_LINUX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define DISABLED_OSX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#elif defined( RPAL_PLATFORM_MACOSX )
#define ENABLED_WINDOWS_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define ENABLED_LINUX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#define ENABLED_OSX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define DISABLED_WINDOWS_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define DISABLED_LINUX_STATEFUL(num,output_event) ENABLED_STATEFUL(num,output_event)
#define DISABLED_OSX_STATEFUL(num,output_event) DISABLED_STATEFUL(num,output_event)
#endif

//=============================================================================
//  Declaration of all stateful detects
//=============================================================================
DECLARE_STATEFUL( 0 );


struct
{
    RBOOL isEnabled;
    StatefulWidget( *create )( );
    rpcm_tag output_event;
    StatefulWidget instance;
} stateful_events[ 1 ] =
{
    ENABLED_STATEFUL(0, RP_TAGS_NOTIFICATION_RECON_BURST )
};


#endif

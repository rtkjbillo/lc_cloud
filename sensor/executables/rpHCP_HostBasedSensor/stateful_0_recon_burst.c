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

#include "stateful_framework.h"
#include "stateful_events.h"

#define RECONS_IN_SEC       (5)
#define RECON_N_PER_BURST   (4)
#define RECON_PROG(progName) { 0, RPCM_STRINGN, 0, RNATIVE_LITERAL( progName ) }
#define RECON_MATCH_PROG(progName) { RPCM_STRINGN, root_file_path, NULL, RECON_PROG(progName), TRUE, 0, RECONS_IN_SEC, FALSE }

#define RECON_TRANSITIONS(isFinal,toState) \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 0 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 1 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 2 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 3 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 4 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 5 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 6 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 7 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 8 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 9 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 10 ]), tr_match ), \
    TRANSITION( isFinal, TRUE, RP_TAGS_NOTIFICATION_NEW_PROCESS, toState, &(recon_progs[ 11 ]), tr_match ), \
    TRANSITION( FALSE, FALSE, 0, 0, &expired, tr_match )

static rpcm_tag root_file_path[] =
{
    RP_TAGS_FILE_PATH,
    RPCM_END_TAG
};

static tr_match_params expired =
{
    0,
    NULL,
    NULL,
    { 0 },
    FALSE,
    RECONS_IN_SEC,
    0,
    TRUE
};

static tr_match_params recon_progs[] =
{
    RECON_MATCH_PROG( "*\\ipconfig.exe" ),
    RECON_MATCH_PROG( "*\\netstat.exe" ),
    RECON_MATCH_PROG( "*\\ping.exe" ),
    RECON_MATCH_PROG( "*\\arp.exe" ),
    RECON_MATCH_PROG( "*\\route.exe" ),
    RECON_MATCH_PROG( "*\\traceroute.exe" ),
    RECON_MATCH_PROG( "*\\nslookup.exe" ),
    RECON_MATCH_PROG( "*\\wmic.exe" ),
    RECON_MATCH_PROG( "*\\net.exe" ),
    RECON_MATCH_PROG( "*\\net?.exe" ),
    RECON_MATCH_PROG( "*\\whoami.exe" ),
    RECON_MATCH_PROG( "*\\systeminfo.exe" )
};

STATE( 0, ARRAY_N_ELEM( recon_progs ) + 1, RECON_TRANSITIONS( FALSE, 1 ) );
STATE( 1, ARRAY_N_ELEM( recon_progs ) + 1, RECON_TRANSITIONS( FALSE, 2 ) );
STATE( 2, ARRAY_N_ELEM( recon_progs ) + 1, RECON_TRANSITIONS( FALSE, 3 ) );
STATE( 3, ARRAY_N_ELEM( recon_progs ) + 1, RECON_TRANSITIONS( TRUE, 0 ) );

STATEFUL_MACHINE( 0, STATEFUL_MACHINE_0_EVENT, RECON_N_PER_BURST, STATE_PTR( 0 ),
                                                                          STATE_PTR( 1 ),
                                                                          STATE_PTR( 2 ),
                                                                          STATE_PTR( 3 ) );

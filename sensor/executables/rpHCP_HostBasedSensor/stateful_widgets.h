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

#ifndef HBS_STATEFUL_WIDGETS_H
#define HBS_STATEFUL_WIDGETS_H

#include <rpal/rpal.h>
#include <librpcm/librpcm.h>
#include <rpHostCommonPlatformLib/rTags.h>

typedef RPVOID StatefulWidget;

typedef struct
{
    rpcm_tag eventType;
    rSequence event;
    rRefCount ref;
    RTIME ts;

} SAMEvent;

typedef struct
{
    rVector events;
    RTIME tsEarliest;
    RTIME tsLatest;

} SAMState;

typedef struct
{
    rVector states;
    RBOOL isDirty;

} SAMStateVector;

StatefulWidget
    SAMTimeBurst
    (
        RU32 within_sec,
        RU32 min_per_burst,
        StatefulWidget feed1,
        ... // NULL terminated list of feeds
    );

StatefulWidget
    SAMSimpleFilter
    (
        rpcm_tag eventType,
        RPVOID matchValue,
        RU32 matchSize,
        rpcm_type findType,
        rpcm_tag* path,
        StatefulWidget feed1,
        ... // NULL terminated list of feeds
    );

StatefulWidget
    SAMOlderOrNewerFilter
    (
        RTIME olderThan,
        RTIME newerThan,
        StatefulWidget feed1,
        ... // NULL terminated list of feeds
    );

SAMStateVector*
    SAMUpdate
    (
        StatefulWidget widget,
        SAMEvent* samEvent
    );

RVOID
    SAMFree
    (
        StatefulWidget widget
    );

SAMEvent*
    SAMEvent_new
    (
        rpcm_tag eventType,
        rSequence event
    );

RVOID
    SAMStateVector_free
    (
        SAMStateVector* statev
    );

#endif

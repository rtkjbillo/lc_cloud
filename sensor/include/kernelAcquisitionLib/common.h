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

#ifndef _KERNEL_ACQUISITION_LIB_COMMON_H
#define _KERNEL_ACQUISITION_LIB_COMMON_H

#ifdef RPAL_PLATFORM_MACOSX
    #define ACQUISITION_COMMS_NAME  "com.refractionpoint.hbs.acq"
#endif

#define ACQUISITION_COMMS_CHALLENGE         0xDEADBEEF
#define ACQUISITION_COMMS_RESPONSE          0x010A020B


#define KERNEL_ACQ_OP_PING                  0
#define KERNEL_ACQ_OP_GET_NEW_PROCESSES     1

typedef struct
{
    void* pArgs;            // Arguments
    int argsSize;           // Size of Arguments
    void* pResult;          // Result of op
    int resultSize;         // Size of results
    void* pSizeUsed;        // Size in results used

} KernelAcqCommand;

//==============================================================================
//  Collector Specific Data Structures
//==============================================================================

// This datastructure matches the processLib processEntry datastructure.
typedef struct
{
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    char path[ 251 ];

} KernelAcqProcess;

#endif
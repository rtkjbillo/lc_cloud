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

//kauth_listener_t g_listener = NULL;
mac_policy_handle_t g_policy = 0;

#define _NUM_BUFFERED_PROCESSES 200

static rMutex g_collector_1_mutex = NULL;
static KernelAcqProcess g_processes[ _NUM_BUFFERED_PROCESSES ] = { 0 };
static uint32_t g_nextProcess = 0;

static struct mac_policy_conf g_policy_conf = { 0 };
static struct mac_policy_ops g_policy_ops = { 0 };

/*
 static int
 new_proc_listener
 (
 kauth_cred_t   credential,
 void *         idata,
 kauth_action_t action,
 uintptr_t      arg0,
 uintptr_t      arg1,
 uintptr_t      arg2,
 uintptr_t      arg3
 )
 */
static int
new_proc_listener
(
 kauth_cred_t cred,
 struct vnode *vp,
 struct vnode *scriptvp,
 struct label *vnodelabel,
 struct label *scriptlabel,
 struct label *execlabel,
 struct componentname *cnp,
 u_int *csflags,
 void *macpolicyattr,
 size_t macpolicyattrlen
 )
{
    /*
     vnode_t prog __unused = (vnode_t)arg0;
     const char* file_path = (const char*)arg1;
     */
    int pathLen = sizeof( g_processes[ 0 ].path );
    pid_t pid = 0;
    pid_t ppid = 0;
    uid_t uid = 0;
    
    //if( KAUTH_FILEOP_EXEC == action )
    //{
    
    uid = kauth_getuid();
    pid = proc_selfpid();
    ppid = proc_selfppid();
    //rpal_debug_info( "!!!!!! process start: %d/%d/%d %s", ppid, pid, uid, file_path );
    
    rpal_mutex_lock( g_collector_1_mutex );
    
    vn_getpath( vp, g_processes[ g_nextProcess ].path, &pathLen );
    g_processes[ g_nextProcess ].pid = pid;
    g_processes[ g_nextProcess ].ppid = ppid;
    g_processes[ g_nextProcess ].uid = uid;
    //strncpy( g_processes[ g_nextProcess ].path,
    //         file_path,
    //         sizeof( g_processes[ g_nextProcess ].path ) - 1 );
    
    g_nextProcess++;
    if( g_nextProcess == _NUM_BUFFERED_PROCESSES )
    {
        g_nextProcess = 0;
        rpal_debug_warning( "overflow of the execution buffer" );
    }
    
    rpal_debug_info( "now %d processes in buffer", g_nextProcess );
    
    rpal_mutex_unlock( g_collector_1_mutex );
    
    //}
    
    //return KAUTH_RESULT_DEFER;
    
    return 0; // Always allow
}

int
task_get_new_processes
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
        rpal_mutex_lock( g_collector_1_mutex );
        toCopy = (*resultSize) / sizeof( KernelAcqProcess );
        
        if( 0 != toCopy )
        {
            toCopy = ( toCopy > g_nextProcess ? g_nextProcess : toCopy );
            
            *resultSize = toCopy * sizeof( KernelAcqProcess );
            memcpy( pResult, g_processes, *resultSize );
            
            g_nextProcess -= toCopy;
            memmove( g_processes, g_processes + toCopy, g_nextProcess );
        }
        
        rpal_mutex_unlock( g_collector_1_mutex );
    }
    else
    {
        ret = EINVAL;
    }
    
    return ret;
}

int
collector_1_initialize
(
 void* d
 )
{
    int isSuccess = 0;
    
    if( NULL != ( g_collector_1_mutex = rpal_mutex_create() ) )
    {
        //g_listener = kauth_listen_scope( KAUTH_SCOPE_FILEOP, new_proc_listener, NULL );
        //if( NULL != g_listener )
        g_policy_ops.mpo_vnode_check_exec = (mpo_vnode_check_exec_t*)new_proc_listener;
        
        g_policy_conf.mpc_name = "rp_hcp_hbs";
        g_policy_conf.mpc_fullname = "LimaCharlie Host Based Sensor";
        g_policy_conf.mpc_labelnames = NULL;
        g_policy_conf.mpc_labelname_count = 0;
        g_policy_conf.mpc_ops = &g_policy_ops;
        g_policy_conf.mpc_loadtime_flags = MPC_LOADTIME_FLAG_UNLOADOK;
        g_policy_conf.mpc_field_off = NULL;
        g_policy_conf.mpc_runtime_flags = 0;
        g_policy_conf.mpc_list = NULL;
        g_policy_conf.mpc_data = NULL;
        
        mac_policy_register( &g_policy_conf, &g_policy, d );
        if( 0 != g_policy )
        {
            isSuccess = 1;
        }
        else
        {
            rpal_mutex_free( g_collector_1_mutex );
        }
    }
    
    return isSuccess;
}

int
collector_1_deinitialize
(

)
{
    rpal_mutex_lock( g_collector_1_mutex );
    //kauth_unlisten_scope( g_listener );
    mac_policy_unregister( g_policy );
    rpal_mutex_free( g_collector_1_mutex );
    return 1;
}
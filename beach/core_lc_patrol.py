# Copyright 2015 refractionPOINT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

REPO_ROOT = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), '..', '..' )

SCALE_DB = [ 'hcp-scale-db' ]

#######################################
# DeploymentManager
# This actor is responsible for 
# managing global deployment related
# configurations, generating keys
# and other information for deployments.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'DeploymentManager',
        initialInstances = 1,
        scalingFactor = 5000,
        actorArgs = ( 'c2/DeploymentManager',
                      [ 'c2/deploymentmanager/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'auditing' : 'c2/audit',
                            'paging' : 'paging',
                            'admin' : 'c2/admin',
                            'sensordir' : 'c2/sensordir/' },
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'deploymentmanagager/afd2a4e5-3319-4c1c-bef7-dc4456d7a235',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'vt/8299a488-7fff-4511-a311-76e6600b4a7a',
                                'paging/31d29b6a-d455-4df7-a196-aec3104f105d',
                                'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'identmanager/f5c3a323-50e5-412a-b711-0e30d8284aa1',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'webhookoutput/4738d18b-4c0c-412c-89e4-b6ecb00904a1',
                                'capabilitymanager/4fe13a22-0ca1-4e1f-aa33-20f045db2fb6',
                                'enrollment/a3bebbb0-00e2-4345-990b-4c36a40b475e',
                                'intake/6058e556-a102-4e51-918e-d36d6d1823db',
                                'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'autotasking/a6cd8d9a-a90c-42ec-bd60-0519b6fb1f64' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# SensorDirectory
# This actor is responsible for keeping
# a list of which sensors are online and
# at which endpoint.
# Parameters:
#######################################
Patrol( 'SensorDirectory',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'c2/SensorDirectory',
                      [ 'c2/sensordir/1.0' ] ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'sensordir/3babff24-400b-4233-bcac-18f538a88fe1',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'taskingproxy/794729aa-1ef5-4930-b377-48dda7b759a5',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'deploymentmanagager/afd2a4e5-3319-4c1c-bef7-dc4456d7a235',
                                'taggingmanagager/693bfd35-80ca-42e1-b0c6-44ef5b27fb59' ],
            'isIsolated' : False,
            'strategy' : 'repulsion' } )


#######################################
# TaggingManager
# This actor is responsible for 
# managing tagging of sensors.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'TaggingManager',
        initialInstances = 1,
        scalingFactor = 5000,
        actorArgs = ( 'c2/TaggingManager',
                      [ 'c2/taggingmanager/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'sensordir' : 'c2/sensordir/',
                            'admin' : 'c2/admin' },
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'taggingmanagager/693bfd35-80ca-42e1-b0c6-44ef5b27fb59',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'enrollment/a3bebbb0-00e2-4345-990b-4c36a40b475e' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# StateUpdater
# This actor is responsible for updating
# the current status of connections with
# sensors.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'StateUpdater',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/StateUpdater',
                      [ 'c2/stateupdater/1.0',
                        'c2/states/updater/1.0' ] ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'stateupdater/d3c521c6-d5c6-4726-9b0c-84d0ac356409',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# AuditManager
# This actor is responsible for managing
# general auditing functions.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'AuditManager',
        initialInstances = 1,
        maxInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/AuditManager',
                      'c2/audit/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'audit/46aa388f-3ceb-4c6c-a36a-0cb6416065f9',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'admin/dde768a4-8f27-4839-9e26-354066c8540e',
                                'identmanager/f5c3a323-50e5-412a-b711-0e30d8284aa1',
                                'dataexporter/dbf240e5-e8df-46ac-8b5e-356a291fdd40',
                                'deploymentmanagager/afd2a4e5-3319-4c1c-bef7-dc4456d7a235' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# EnrollmentManager
# This actor is responsible for managing
# enrollment requests from sensors.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
# enrollment_token: secret token used
#    to verify enrolled sensor identities.
#######################################
Patrol( 'EnrollmentManager',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/EnrollmentManager',
                      'c2/enrollments/1.0' ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager',
                            'tagging' : 'c2/taggingmanager' },
            'parameters' : { 'db' : SCALE_DB,
                             'enrollment_token' : '595f06f1-49cf-48fe-8410-8706dc469116' },
            'secretIdent' : 'enrollment/a3bebbb0-00e2-4345-990b-4c36a40b475e',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'admin/dde768a4-8f27-4839-9e26-354066c8540e',
                                'identmanager/f5c3a323-50e5-412a-b711-0e30d8284aa1' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# TaskingProxy
# This actor is responsible for proxying
# various taskings from actors in the
# cloud to the relevant endpoint and sensors.
# Parameters:
#######################################
Patrol( 'TaskingProxy',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/TaskingProxy',
                      [ 'c2/taskingproxy/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'sensor_dir' : 'c2/sensordir/' },
            'parameters' : {},
            'secretIdent' : 'taskingproxy/794729aa-1ef5-4930-b377-48dda7b759a5',
            'trustedIdents' : [ 'autotasking/a6cd8d9a-a90c-42ec-bd60-0519b6fb1f64',
                                'admin/dde768a4-8f27-4839-9e26-354066c8540e',
                                'persistenttasking/54158388-2b0b-47c0-9642-f90835b5057b' ],
            'isIsolated' : False,
            'strategy' : 'repulsion' } )

#######################################
# ModuleManager
# This actor is responsible for syncing
# with sensors and keeping their loaded
# modules up to date.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'ModuleManager',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/ModuleManager',
                      [ 'c2/modulemanager/1.0' ] ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'modulemanager/1ecf1cd3-044d-434d-9134-b9b2c976ccad',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'admin/dde768a4-8f27-4839-9e26-354066c8540e' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# AdminEndpoint
# This actor will serve as a comms
# endpoint by the admin_lib/cli
# to administer the LC.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'AdminEndpoint',
        initialInstances = 1,
        scalingFactor = 5000,
        actorArgs = ( 'c2/AdminEndpoint',
                      'c2/admin/1.0' ),
        actorKwArgs = {
            'resources' : { 'auditing' : 'c2/audit',
                            'enrollments' : 'c2/enrollments',
                            'module_tasking' : 'c2/modulemanager',
                            'hbs_profiles' : 'c2/hbsprofilemanager',
                            'tasking_proxy' : 'c2/taskingproxy/',
                            'persistent_tasks' : 'c2/persistenttasking/' },
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'admin/dde768a4-8f27-4839-9e26-354066c8540e',
            'trustedIdents' : [ 'cli/955f6e63-9119-4ba6-a969-84b38bfbcc05',
                                'deploymentmanagager/afd2a4e5-3319-4c1c-bef7-dc4456d7a235' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# HbsProfileManager
# This actor is responsible for syncing
# with sensors to keep HBS profiles up
# to date.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'HbsProfileManager',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/HbsProfileManager',
                      [ 'c2/hbsprofilemanager/1.0' ] ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'hbsprofilemanager/8326405a-0698-4a91-9b30-d4ef9e4b9926',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                                'admin/dde768a4-8f27-4839-9e26-354066c8540e' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# IdentManager
# This actor is responsible for adding
# and authenticating users.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'IdentManager',
        initialInstances = 1,
        scalingFactor = 5000,
        actorArgs = ( 'c2/IdentManager',
                      [ 'c2/identmanager/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'auditing' : 'c2/audit',
                            'paging' : 'paging',
                            'enrollments' : 'c2/enrollments',
                            'deployment' : 'c2/deploymentmanager' },
            'parameters' : { 'db' : SCALE_DB },
            'secretIdent' : 'identmanager/f5c3a323-50e5-412a-b711-0e30d8284aa1',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                                'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075',
                                'webhookoutput/4738d18b-4c0c-412c-89e4-b6ecb00904a1' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

###############################################################################
# Analysis Intake
###############################################################################

#######################################
# AutoTasking
# This actor receives tasking requests
# from other Actors (detection Actors
# for now), applies a QoS and tasks.
# Parameters:
# _hbs_key: the private HBS key to task.
# sensor_qph: the maximum number of
#    taskings per hour per sensor.
# global_qph: the maximum number of
#    tasking per hour globally.
# allowed: the list of CLI commands
#    that can be tasked.
#######################################
Patrol( 'AutoTasking',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/AutoTasking',
                      'analytics/autotasking/1.0' ),
        actorKwArgs = {
            'resources' : { 'modeling' : 'models/',
                            'deployment' : 'c2/deploymentmanager' },
            'parameters' : { 'db' : SCALE_DB,
                             'sensor_qph' : 100,
                             'global_qph' : 1000,
                             'allowed' : [ 'file_info',
                                           'file_hash',
                                           'file_get',
                                           'dir_list',
                                           'doc_cache_get',
                                           'mem_map',
                                           'mem_strings',
                                           'mem_handles',
                                           'os_processes',
                                           'hidden_module_scan',
                                           'exec_oob_scan',
                                           'history_dump',
                                           'exfil_add',
                                           'hollowed_module_scan',
                                           'os_services',
                                           'os_drivers',
                                           'os_autoruns',
                                           'os_kill_process',
                                           'os_suspend',
                                           'yara_update',
                                           'deny_tree',
                                           'segregate_network',
                                           'rejoin_network' ],
                             'log_file' : './admin_cli.log' },
            'secretIdent' : 'autotasking/a6cd8d9a-a90c-42ec-bd60-0519b6fb1f64',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075' ],
            'isIsolated' : True } )

#######################################
# AnalyticsIntake
# This actor receives the messages from
# the beacons and does initial parsing
# of components that will be of
# interest to all analytics and then
# forwards it on to other components.
#######################################
Patrol( 'AnalyticsIntake',
        initialInstances = 1,
        scalingFactor = 500,
        actorArgs = ( 'analytics/AnalyticsIntake',
                      'analytics/intake/1.0' ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager',
                            'stateless' : 'analytics/stateless/intake',
                            'stateful' : 'analytics/stateful/intake',
                            'modeling' : 'analytics/modeling/intake',
                            'investigation' : 'analytics/investigation/intake',
                            'relation_builder' : 'analytics/async/relbuilder' },
            'parameters' : {},
            'secretIdent' : 'intake/6058e556-a102-4e51-918e-d36d6d1823db',
            'trustedIdents' : [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd' ],
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# AnalyticsInvestigation
# This actor responsible for sending
# messages to the actors interested in
# specific investigations.
# Parameters:
# ttl: the number of seconds the data
#    flow for an investigation remains
#    open after last data seen.
#######################################
Patrol( 'AnalyticsInvestigation',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'analytics/AnalyticsInvestigation',
                      'analytics/investigation/intake/1.0' ),
        actorKwArgs = {
            'resources' : { 'investigations' : 'analytics/inv_id/%s' },
            'parameters' : { 'ttl' : ( 60 * 60 * 24 ) },
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ] } )

#######################################
# HuntsManager
# This actor manages the registration
# and configuration of the various
# automated hunts.
# Parameters:
#######################################
Patrol( 'HuntsManager',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/HuntsManager',
                      'analytics/huntsmanager/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'huntsmanager/d666cbc3-38d5-4086-b9ce-c543625ee45c',
            'trustedIdents' : [ 'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075' ] } )

#######################################
# AnalyticsModeling
# This actor is responsible to model
# and record the information extracted
# from the messages in all the different
# pre-pivoted databases.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'AnalyticsModeling',
        initialInstances = 1,
        scalingFactor = 100,
        actorArgs = ( 'analytics/AnalyticsModeling',
                      [ 'analytics/modeling/intake/1.0',
                        'analytics/modeling/inv/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager',
                            'identmanager' : 'c2/identmanager' },
            'parameters' : { 'db' : SCALE_DB,
                             'retention_raw_events' : ( 60 * 60 * 24 * 14 ),
                             'retention_investigations' : ( 60 * 60 * 24 * 30 ),
                             'retention_objects_primary' : ( 60 * 60 * 24 * 365 ),
                             'retention_objects_secondary' : ( 60 * 60 * 24 * 30 * 6 ),
                             'retention_explorer' : ( 60 * 60 * 24 * 30 ) },
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
            'isIsolated' : True,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# ModelView
# This actor is responsible to query
# the model to retrieve different
# advanced queries for UI or for
# other detection mechanisms.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'AnalyticsModelView',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'analytics/ModelView',
                      'models/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'scale_db' : SCALE_DB },
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'assistant/2f25cc4a-7386-42c2-af64-04fca2503086',
                                'vt/8299a488-7fff-4511-a311-76e6600b4a7a',
                                'dataexporter/dbf240e5-e8df-46ac-8b5e-356a291fdd40',
                                'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'autotasking/a6cd8d9a-a90c-42ec-bd60-0519b6fb1f64' ],
            'isIsolated' : True,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# PagingActor
# This actor responsible for sending
# pages by email.
# Parameters:
# from: email/user to send page from.
# password: password of the account
#    used to send.
# smtp_server: URI of the smtp server.
# smtp_port: port of the smtp server.
#######################################
Patrol( 'PagingActor',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'PagingActor',
                      'paging/1.0' ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager' },
            'parameters' : {},
            'secretIdent' : 'paging/31d29b6a-d455-4df7-a196-aec3104f105d',
            'trustedIdents' : [ 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                'identmanager/f5c3a323-50e5-412a-b711-0e30d8284aa1',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'strategy' : 'repulsion' } )

#######################################
# DataExporter
# This actor is responsible for exporting
# all types of data collected by LC into
# various formats.
# Parameters:
#######################################
Patrol( 'DataExporter',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'analytics/DataExporter',
                      [ 'analytics/dataexporter/1.0' ] ),
        actorKwArgs = {
            'resources' : { 'models' : 'models/',
                            'auditing' : 'c2/audit' },
            'parameters' : {},
            'secretIdent' : 'dataexporter/dbf240e5-e8df-46ac-8b5e-356a291fdd40',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ],
            'isIsolated' : True,
            'strategy' : 'repulsion' } )

#######################################
# VirusTotalActor
# This actor retrieves VT reports while
# caching results.
# Parameters:
# _key: the VT API Key.
# qpm: maximum number of queries to
#    to VT per minute, based on your
#    subscription level, default of 4
#    which matches their free tier.
# cache_size: how many results to cache.
# ttl: number of seconds each report is
# valid.
#######################################
Patrol( 'VirusTotalActor',
        initialInstances = 1,
        scalingFactor = 2000,
        actorArgs = ( 'analytics/VirusTotalActor',
                      'analytics/virustotal/1.0' ),
        actorKwArgs = {
            'resources' : { 'modeling' : 'models',
                            'deployment' : 'c2/deploymentmanager' },
            'parameters' : { 'qpm' : 4,
                             'ttl' : ( 60 * 60 * 24 * 30 ) },
            'secretIdent' : 'vt/8299a488-7fff-4511-a311-76e6600b4a7a',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517' ] } )

#######################################
# GeoLocationActor
# This actor IP address geolocation.
# Parameters:
#
#######################################
Patrol( 'GeoLocationActor',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/GeoLocationActor',
                      'analytics/geolocation/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'geolocation/649a9dd2-bfba-46d1-8247-bbd1096703ca',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'blink/6babf560-88db-403d-a5f6-3689397e0104',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ],
            'isIsolated' : False } )

#######################################
# AlexaDNS
# This actor retrieves the list of Alexa
# top domains to be queried against as
# a list of likely legitimate domains.
# Parameters:
#
#######################################
Patrol( 'AlexaDNS',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/AlexaDNS',
                      'analytics/alexadns/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'alexadns/e1527553-815b-4dd5-8a40-708a287605b4',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'blink/6babf560-88db-403d-a5f6-3689397e0104' ],
            'isIsolated' : True,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# MalwareDomains
# This actor retrieves the list of domains
# compiled by MalwareDomains.com to 
# be queried against as a list of known bad.
# Parameters:
#
#######################################
Patrol( 'MalwareDomains',
        initialInstances = 2,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/MalwareDomains',
                      'analytics/malwaredomains/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'malwaredomains/d7e813ef-e47d-479c-a56e-0190cad45c25',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'blink/6babf560-88db-403d-a5f6-3689397e0104' ],
            'isIsolated' : True,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# AnalyticsStateless
# This actor responsible for sending
# messages of the right type to the
# right stateless detection actors.
#######################################
Patrol( 'AnalyticsStateless',
        initialInstances = 1,
        scalingFactor = 2000,
        actorArgs = ( 'analytics/AnalyticsStateless',
                      'analytics/stateless/intake/1.0' ),
        actorKwArgs = {
            'resources' : { 'all' : 'analytics/stateless/all/',
                            'output' : 'analytics/output/events/',
                            'specific' : 'analytics/stateless/%s/%s/' },
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
            'is_drainable' : True } )

#######################################
# AnalyticsStateful
# This actor responsible for sending
# messages of the right type to the
# right stateful detection actors.
#######################################
Patrol( 'AnalyticsStateful',
        initialInstances = 1,
        scalingFactor = 500,
        actorArgs = ( 'analytics/AnalyticsStateful',
                      'analytics/stateful/intake/1.0' ),
        actorKwArgs = {
            'resources' : { 'modules' : 'analytics/stateful/modules/%s/' },
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
            'is_drainable' : True } )

#######################################
# AnalyticsReporting
# This actor receives Detecs from the
# stateless and stateful detection
# actors and ingest them into the
# reporting pipeline.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
# paging_dest: email addresses to page.
#######################################
Patrol( 'AnalyticsReporting',
        initialInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/AnalyticsReporting',
                      'analytics/reporting/1.0' ),
        actorKwArgs = {
            'resources' : { 'output' : 'analytics/output/detects',
                            'paging' : 'paging',
                            'identmanager' : 'c2/identmanager',
                            'modeling' : 'models' },
            'parameters' : { 'db' : SCALE_DB,
                             'paging_dest' : [],
                             'retention_investigations' : 60 * 60 * 24 * 7 },
            'secretIdent' : 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ],
            'isIsolated' : True } )

#######################################
# CapabilityManager
# This actor manages backend capabilities
# loaded as stateless, stateful or hunters.
# Parameters:
#######################################
Patrol( 'CapabilityManager',
        initialInstances = 1,
        maxInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/CapabilityManager',
                      'analytics/capabilitymanager/1.0' ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager' },
            'parameters' : { 'scale' : 50,
                             'detect_secret_ident' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                             'hunter_secret_ident' : 'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                             'detect_trusted_ident' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                             'hunter_trusted_ident' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' },
            'secretIdent' : 'capabilitymanager/4fe13a22-0ca1-4e1f-aa33-20f045db2fb6',
            'trustedIdents' : [ 'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ] } )

#######################################
# BlinkModel
# This actor is responsible for managing
# enrollment requests from sensors.
# Parameters:
# db: the Cassandra seed nodes to
#    connect to for storage.
# rate_limit_per_sec: number of db ops
#    per second, limiting to avoid
#    db overload since C* is bad at that.
# max_concurrent: number of concurrent
#    db queries.
# block_on_queue_size: stop queuing after
#    n number of items awaiting ingestion.
#######################################
Patrol( 'BlinkModel',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'analytics/BlinkModel',
                      'analytics/blinkmodel/1.0' ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : { 'scale_db' : SCALE_DB },
            'secretIdent' : 'blink/6babf560-88db-403d-a5f6-3689397e0104',
            'trustedIdents' : [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ],
            'isIsolated' : True,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# EndpointProcessor
# This actor will process incoming
# connections from the sensors.
# Parameters:
# _priv_key: the C2 private key.
# handler_port_*: start and end port
#    where incoming connections will
#    be processed.
# handler_address: the ip address to do
#    a listen on.
# handler_interface: the network interface
#    to listen on, overrides handler_address.
#######################################
Patrol( 'EndpointProcessor',
        initialInstances = 1,
        scalingFactor = 1000,
        actorArgs = ( 'c2/EndpointProcessor',
                      'c2/endpoint/1.0' ),
        actorKwArgs = {
            'resources' : { 'analytics' : 'analytics/intake',
                            'enrollments' : 'c2/enrollments',
                            'states' : 'c2/states/',
                            'sensordir' : 'c2/sensordir/',
                            'module_tasking' : 'c2/modulemanager',
                            'hbs_profiles' : 'c2/hbsprofilemanager',
                            'deployment' : 'c2/deploymentmanager',
                            'tagging' : 'c2/taggingmanager' },
            'parameters' : { 'handler_interface' : 'eth1',
                             'sensor_max_qps' : 30 },
            'secretIdent' : 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
            'trustedIdents' : [ 'taskingproxy/794729aa-1ef5-4930-b377-48dda7b759a5',
                                'endpointproxy/8e7a890b-8016-4396-b012-aec73d055dd6' ],
            'isIsolated' : False,
            'strategy' : 'repulsion',
            'is_drainable' : True } )

#######################################
# SlackRep
# This actor receives Detecs from the
# stateless and stateful detection
# actors and reports them on Slack.
# Parameters:
#######################################
Patrol( 'SlackRep',
        initialInstances = 1,
        maxInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/SlackRep',
                      [ 'analytics/slackrep/1.0',
                        'analytics/output/detects/slack' ] ),
        actorKwArgs = {
            'resources' : { 'modeling' : 'models',
                            'auditing' : 'c2/audit',
                            'deployment' : 'c2/deploymentmanager',
                            'sensordir' : 'c2/sensordir/',
                            'identmanager' : 'c2/identmanager',
                            'autotasking' : 'analytics/autotasking',
                            'huntsmanager' : 'analytics/huntsmanager',
                            'reporting' : 'analytics/reporting' },
            'parameters' : {},
            'secretIdent' : 'slackrep/20546efe-0f84-46f2-b9ca-f17bf5997075',
            'trustedIdents' : [ 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'isIsolated' : True } )

#######################################
# FileEventsOutput
# This actor receives Detecs from the
# stateless and stateful detection
# actors and reports them to a log file.
# Parameters:.
#######################################
Patrol( 'FileEventsOutput',
        initialInstances = 1,
        maxInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/FileEventsOutput',
                      [ 'analytics/fileeventsoutput/1.0',
                        'analytics/output/detects/fileevent',
                        'analytics/output/events/fileevent' ] ),
        actorKwArgs = {
            'resources' : {},
            'parameters' : {},
            'secretIdent' : 'fileeventsoutput/9a6e2317-db95-4a93-b815-b3c1aaecf527',
            'trustedIdents' : [ 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'isIsolated' : False } )

#######################################
# WebHookOutput
# This actor receives Detecs from the
# stateless and stateful detection
# actors and reports them to a per org
# webhook.
# Parameters:.
#######################################
Patrol( 'WebHookOutput',
        initialInstances = 1,
        maxInstances = 1,
        scalingFactor = 10000,
        actorArgs = ( 'analytics/WebHookOutput',
                      [ 'analytics/webhookoutput/1.0',
                        'analytics/output/detects/webhookoutput' ] ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager',
                            'identmanager' : 'c2/identmanager' },
            'parameters' : {},
            'secretIdent' : 'webhookoutput/4738d18b-4c0c-412c-89e4-b6ecb00904a1',
            'trustedIdents' : [ 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                                'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'isIsolated' : False } )

#######################################
# QuickDetectHost
# This actor responsible for hosting and
# managing all the quick detections.
#######################################
Patrol( 'QuickDetectHost',
        initialInstances = 1,
        scalingFactor = 2000,
        actorArgs = ( 'analytics/QuickDetectHost',
                      [ 'analytics/stateless/quickdetect/1.0',
                        'analytics/stateless/all/quickhost' ] ),
        actorKwArgs = {
            'resources' : { 'deployment' : 'c2/deploymentmanager',
                            'tagging' : 'c2/taggingmanager',
                            'modeling' : 'models',
                            'paging' : 'paging',
                            'autotasking' : 'analytics/autotasking',
                            'reporting' : 'analytics/reporting' },
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
                                'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903' ],
            'isIsolated' : True,
            'is_drainable' : True,
            'strategy' : 'repulsion' } )

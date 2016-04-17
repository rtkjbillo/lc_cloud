import os
import sys
from beach.beach_api import Beach
import logging

REPO_ROOT = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), '..', '..' )

if os.geteuid() != 0:
    print( 'Not currently running as root. If you meant to run this as part of the Cloud-in-a-Can you should run this with sudo.' )

if 1 < len( sys.argv ):
    BEACH_CONFIG_FILE = os.path.abspath( sys.argv[ 1 ] )
else:
    BEACH_CONFIG_FILE = os.path.join( os.path.dirname( os.path.abspath( __file__ ) ), 'sample_cluster.yaml' )

beach = Beach( BEACH_CONFIG_FILE, realm = 'hcp' )

if not beach.flush():
    print( "Could not flush Beach cluster. Are you sure it is running?" )
    sys.exit(-1)

#######################################
# BeaconProcessor
# This actor will process incoming
# beacons from the sensors.
# Parameters:
# state_db: these are the connection
#    details for the mysql database
#    used to store the low-importance
#    data tracked at runtime.
# deployment_key: The deployment key
#    to enforce if needed, it helps
#    to filter out sensors beaconing
#    to you that are not related to
#    your deployment.
# _priv_key: the C2 private key.
# task_back_timeout: the number of
#    seconds to wait during each
#    beacon to give a chance to any
#    detects to generate tasks for
#    the sensor to process right away.
#######################################
print( beach.addActor( 'c2/BeaconProcessor',
                       'c2/beacon/1.0',
                       parameters = { 'state_db' : { 'url' : 'hcp-state-db',
                                                     'db' : 'hcp',
                                                     'user' : 'root',
                                                     'password' : 'letmein' },
                                      'deployment_key' : 'sample_hcp_deployment_key',
                                      '_priv_key' : open( os.path.join( REPO_ROOT,
                                                                        'keys',
                                                                        'c2.priv.pem' ), 'r' ).read(),
                                      'task_back_timeout' : 2 },
                       secretIdent = 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd',
                       trustedIdents = [ 'http/5bc10821-2d3f-413a-81ee-30759b9f863b' ],
                       n_concurrent = 5 ) )

#######################################
# AdminEndpoint
# This actor will serve as a comms
# endpoint by the admin_lib/cli
# to administer the LC.
# Parameters:
# state_db: these are the connection
#    details for the mysql database
#    used to store low-importance
#    data tracked at runtime.
#######################################
print( beach.addActor( 'c2/AdminEndpoint',
                       'c2/admin/1.0',
                       parameters = { 'state_db' : { 'url' : 'hcp-state-db',
                                                     'db' : 'hcp',
                                                     'user' : 'root',
                                                     'password' : 'letmein' } },
                       secretIdent = 'admin/dde768a4-8f27-4839-9e26-354066c8540e',
                       trustedIdents = [ 'cli/955f6e63-9119-4ba6-a969-84b38bfbcc05' ],
                       n_concurrent = 5 ) )

###############################################################################
# Analysis Intake
###############################################################################

#######################################
# AnalyticsIntake
# This actor receives the messages from
# the beacons and does initial parsing
# of components that will be of
# interest to all analytics and then
# forwards it on to other components.
#######################################
print( beach.addActor( 'analytics/AnalyticsIntake',
                       'analytics/intake/1.0',
                       parameters = {  },
                       secretIdent = 'intake/6058e556-a102-4e51-918e-d36d6d1823db',
                       trustedIdents = [ 'beacon/09ba97ab-5557-4030-9db0-1dbe7f2b9cfd' ],
                       n_concurrent = 5 ) )

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
print( beach.addActor( 'analytics/AnalyticsModeling',
                       'analytics/modeling/intake/1.0',
                       parameters = { 'db' : [ 'hcp-scale-db' ],
                                      'rate_limit_per_sec' : 200,
                                      'max_concurrent' : 5,
                                      'block_on_queue_size' : 200000 },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
                       n_concurrent = 5,
                       isIsolated = True ) )

#######################################
# AnalyticsStateless
# This actor responsible for sending
# messages of the right type to the
# right stateless detection actors.
#######################################
print( beach.addActor( 'analytics/AnalyticsStateless',
                       'analytics/stateless/intake/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
                       n_concurrent = 5 ) )

#######################################
# AnalyticsStateful
# This actor responsible for sending
# messages of the right type to the
# right stateful detection actors.
#######################################
print( beach.addActor( 'analytics/AnalyticsStateful',
                       'analytics/stateful/intake/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
                       n_concurrent = 5 ) )

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
print( beach.addActor( 'analytics/AnalyticsReporting',
                       'analytics/reporting/1.0',
                       parameters = { 'db' : [ 'hcp-scale-db' ],
                                      'rate_limit_per_sec' : 10,
                                      'max_concurrent' : 5,
                                      'block_on_queue_size' : 200000,
                                      'paging_dest' : [] },
                       secretIdent = 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                                         'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517' ],
                       n_concurrent = 5,
                       isIsolated = True ) )

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
print( beach.addActor( 'analytics/AnalyticsInvestigation',
                       'analytics/investigation/intake/1.0',
                       parameters = { 'ttl' : ( 60 * 60 * 24 ) },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'intake/6058e556-a102-4e51-918e-d36d6d1823db' ],
                       n_concurrent = 5 ) )

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
print( beach.addActor( 'analytics/ModelView',
                       'models/1.0',
                       parameters = { 'scale_db' : [ 'hcp-scale-db' ],
                                      'state_db' : { 'url' : 'hcp-state-db',
                                                     'db' : 'hcp',
                                                     'user' : 'root',
                                                     'password' : 'letmein' },
                                      'rate_limit_per_sec' : 500,
                                      'max_concurrent' : 10,
                                      'beach_config' : BEACH_CONFIG_FILE },
                       trustedIdents = [ 'lc/0bf01f7e-62bd-4cc4-9fec-4c52e82eb903',
                                         'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517',
                                         'rest/be41bb0f-449a-45e9-87d8-ef4533336a2d' ],
                       n_concurrent = 5,
                       isIsolated = True ) )

#######################################
# AutoTasking
# This actor receives tasking requests
# from other Actors (detection Actors
# for now), applies a QoS and tasks.
# Parameters:
# _hbs_key: the private HBS key to task.
# beach_config: the path to the beach
#    config file.
# sensor_qph: the maximum number of
#    taskings per hour per sensor.
# global_qph: the maximum number of
#    tasking per hour globally.
# allowed: the list of CLI commands
#    that can be tasked.
#######################################
print( beach.addActor( 'analytics/AutoTasking',
                       'analytics/autotasking/1.0',
                       parameters = { '_hbs_key' : open( os.path.join( REPO_ROOT,
                                                                       'keys',
                                                                       'hbs_root.priv.der' ), 'r' ).read(),
                                      'beach_config' : BEACH_CONFIG_FILE,
                                      'sensor_qph' : 100,
                                      'global_qph' : 1000,
                                      'allowed' : [ 'file_info',
                                                    'file_hash',
                                                    'mem_map',
                                                    'mem_strings',
                                                    'mem_handles',
                                                    'os_processes',
                                                    'hidden_module_scan',
                                                    'exec_oob_scan',
                                                    'history_dump',
                                                    'remain_live',
                                                    'exfil_add',
                                                    'critical_add',
                                                    'hollowed_module_scan',
                                                    'os_services',
                                                    'os_drivers',
                                                    'os_autoruns',
                                                    'yara_update' ],
                                      'log_file' : './admin_cli.log' },
                       secretIdent = 'autotasking/a6cd8d9a-a90c-42ec-bd60-0519b6fb1f64',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                                         'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517' ],
                       n_concurrent = 5 ) )

#######################################
# HuntsManager
# This actor manages the registration
# and configuration of the various
# automated hunts.
# Parameters:
# beach_config: the path to the beach
#    config file.
#######################################
print( beach.addActor( 'analytics/HuntsManager',
                       'analytics/huntsmanager/1.0',
                       parameters = { 'beach_config' : BEACH_CONFIG_FILE },
                       secretIdent = 'huntsmanager/d666cbc3-38d5-4086-b9ce-c543625ee45c',
                       trustedIdents = [ 'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517' ],
                       n_concurrent = 5 ) )

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
print( beach.addActor( 'PagingActor',
                       'paging/1.0',
                       parameters = {  },
                       secretIdent = 'paging/31d29b6a-d455-4df7-a196-aec3104f105d',
                       trustedIdents = [ 'reporting/9ddcc95e-274b-4a49-a003-c952d12049b8' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/VirusTotalActor
# This actor retrieves VT reports while
# caching results.
# Parameters:
# _key: the VT API Key.
# qpm: maximum number of queries to
#    to VT per minute, based on your
#    subscription level, default of 4
#    which matches their free tier.
# cache_size: how many results to cache.
#######################################
print( beach.addActor( 'analytics/VirusTotalActor',
                       [ 'analytics/virustotal/1.0' ],
                       parameters = { 'qpm' : 4 },
                       secretIdent = 'virustotal/697bfbf7-aa78-41f3-adb8-26f59bdba0da',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                                         'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517' ],
                       n_concurrent = 1 ) )

###############################################################################
# Stateless Detection
###############################################################################

#######################################
# stateless/TestDetection
# This actor simply looks for a
# file_path containing the string
# 'hcp_evil_detection_test' and generates
# a detect and a file_hash tasking for it.
#######################################
print( beach.addActor( 'analytics/stateless/TestDetection',
                       'analytics/stateless/common/notification.NEW_PROCESS/testdetection/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/WinSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
print( beach.addActor( 'analytics/stateless/WinSuspExecLoc',
                       [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecloc/1.0',
                         'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecloc/1.0' ],
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/WinSuspExecName
# This actor looks for execution from
# executables with suspicious names that
# try to hide the fact the files are
# executables.
#######################################
print( beach.addActor( 'analytics/stateless/WinSuspExecName',
                       [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecname/1.0',
                         'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecname/1.0' ],
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/MacSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
print( beach.addActor( 'analytics/stateless/MacSuspExecLoc',
                       [ 'analytics/stateless/osx/notification.NEW_PROCESS/suspexecloc/1.0',
                         'analytics/stateless/osx/notification.CODE_IDENTITY/suspexecloc/1.0', ],
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/BatchSelfDelete
# This actor looks for patterns of an
# executable deleteing itself using
# a batch script.
#######################################
print( beach.addActor( 'analytics/stateless/BatchSelfDelete',
                       'analytics/stateless/windows/notification.NEW_PROCESS/batchselfdelete/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/KnownObjects
# This actor looks for known Objects
# in all messages. It receives those
# known Objects from another actor
# source that can be customized.
# Parameters:
# source: the beach category to query
#    to receive the known Objects.
# source_refresh_sec: how often to
#    refresh its known Objects from
#    the source.
#######################################
print( beach.addActor( 'analytics/stateless/KnownObjects',
                       [ 'analytics/stateless/common/notification.NEW_PROCESS/knownobjects/1.0',
                         'analytics/stateless/common/notification.CODE_IDENTITY/knownobjects/1.0',
                         'analytics/stateless/common/notification.OS_SERVICES_REP/knownobjects/1.0',
                         'analytics/stateless/common/notification.OS_DRIVERS_REP/knownobjects/1.0',
                         'analytics/stateless/common/notification.OS_AUTORUNS_REP/knownobjects/1.0',
                         'analytics/stateless/common/notification.DNS_REQUEST/knownobjects/1.0' ],
                       parameters = { 'source' : 'sources/known_objects/',
                                      'source_refresh_sec' : 3600 },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/VirusTotalKnownBad
# This actor checks all hashes against
# VirusTotal and reports hashes that
# have more than a threshold of AV
# reports, while caching results.
# Parameters:
# _key: the VT API Key.
# min_av: minimum number of AV reporting
#    a result on the hash before it is
#    reported as a detection.
#######################################
print( beach.addActor( 'analytics/stateless/VirusTotalKnownBad',
                       [ 'analytics/stateless/common/notification.CODE_IDENTITY/virustotalknownbad/1.0',
                         'analytics/stateless/common/notification.OS_SERVICES_REP/virustotalknownbad/1.0',
                         'analytics/stateless/common/notification.OS_DRIVERS_REP/virustotalknownbad/1.0',
                         'analytics/stateless/common/notification.OS_AUTORUNS_REP/virustotalknownbad/1.0' ],
                       parameters = { 'qpm' : 1 },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 2 ) )

#######################################
# stateless/WinFirewallCliMods
# This actor looks for patterns of an
# executable adding firewall rules
# via a command line interface.
#######################################
print( beach.addActor( 'analytics/stateless/WinFirewallCliMods',
                       'analytics/stateless/windows/notification.NEW_PROCESS/firewallclimods/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/HiddenModules
# This actor looks hidden module
# notifications.
#######################################
print( beach.addActor( 'analytics/stateless/HiddenModules',
                       'analytics/stateless/common/notification.HIDDEN_MODULE_DETECTED/hiddenmodules/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/WinOobExec
# This actor looks OOB execution
# notifications.
#######################################
print( beach.addActor( 'analytics/stateless/WinOobExec',
                       'analytics/stateless/windows/notification.EXEC_OOB/oobexec/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/ExecNotOnDisk
# This actor for code loading from disk
# but not visible on disk. In other
# words it has a code ident but no hash.
#######################################
print( beach.addActor( 'analytics/stateless/ExecNotOnDisk',
                       'analytics/stateless/common/notification.CODE_IDENTITY/execnotondisk/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/HollowedProcess
# This actor for mismatch between a
# module on disk and in memory for
# signs of process hollowing.
#######################################
print( beach.addActor( 'analytics/stateless/HollowedProcess',
                       [ 'analytics/stateless/windows/notification.MODULE_MEM_DISK_MISMATCH/hollowedprocess/1.0',
                         'analytics/stateless/linux/notification.MODULE_MEM_DISK_MISMATCH/hollowedprocess/1.0' ],
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/YaraDetects
# This actor generates detects from
# sensor events with Yara detections.
#######################################
print( beach.addActor( 'analytics/stateless/YaraDetects',
                       [ 'analytics/stateless/common/notification.YARA_DETECTION/yaradetects/1.0' ],
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateless/YaraUpdater
# This actor does not generate detects,
# it merely updates new sensor coming
# online with the most recent Yara rules.
#######################################
print( beach.addActor( 'analytics/stateless/YaraUpdater',
                       [ 'analytics/stateless/common/notification.STARTING_UP/yaraupdater/1.0' ],
                       parameters = { 'rules_dir' : 'hcp/analytics/yara_rules/',
                                      'remote_rules' : { 'windows/yararules.com.yar' : 'http://yararules.com/rules/malware.yar' } },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

###############################################################################
# Stateful Detection
###############################################################################
#######################################
# stateful/WinDocumentExploit
# This actor looks for various stateful
# patterns indicating documents being
# exploited.
#######################################
print( beach.addActor( 'analytics/stateful/WinDocumentExploit',
                       'analytics/stateful/modules/windows/documentexploit/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )
print( beach.addActor( 'analytics/stateful/WinDocumentExploit',
                       'analytics/stateful/modules/windows/documentexploit/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateful/SensorIssues
# This actor looks for issues with the
# sensor.
#######################################
print( beach.addActor( 'analytics/stateful/SensorIssues',
                       'analytics/stateful/modules/common/sensorissues/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )
print( beach.addActor( 'analytics/stateful/SensorIssues',
                       'analytics/stateful/modules/common/sensorissues/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateful/WinReconTools
# This actor looks for burst in usage
# of common recon tools used early
# during exploitation.
#######################################
print( beach.addActor( 'analytics/stateful/WinReconTools',
                       'analytics/stateful/modules/windows/recontools/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )
print( beach.addActor( 'analytics/stateful/WinReconTools',
                       'analytics/stateful/modules/windows/recontools/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

#######################################
# stateful/MacReconTools
# This actor looks for burst in usage
# of common recon tools used early
# during exploitation.
#######################################
print( beach.addActor( 'analytics/stateful/MacReconTools',
                       'analytics/stateful/modules/osx/recontools/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )
print( beach.addActor( 'analytics/stateful/MacReconTools',
                       'analytics/stateful/modules/osx/recontools/1.0',
                       parameters = {  },
                       secretIdent = 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

###############################################################################
# Hunts
###############################################################################
print( beach.addActor( 'analytics/hunt/SampleHunt',
                       'analytics/hunt/samplehunt/1.0',
                       parameters = {  },
                       secretIdent = 'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

print( beach.addActor( 'analytics/hunt/SuspectedDropperHunt',
                       'analytics/hunt/suspecteddropperhunt/1.0',
                       parameters = {  },
                       secretIdent = 'hunt/8e0f55c0-6593-4747-9d02-a4937fa79517',
                       trustedIdents = [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
                       n_concurrent = 5 ) )

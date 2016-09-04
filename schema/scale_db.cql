CREATE KEYSPACE "hcp_analytics" WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 3 };

use hcp_analytics;

CREATE TABLE sensor_states(
  org int,
  subnet int,
  unique int,
  platform int,
  enroll timestamp,
  alive timestamp,
  dead timestamp,
  ext_ip varchar,
  int_ip varchar,
  hostname varchar,
  PRIMARY KEY( org, subnet, unique, platform )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE sensor_hostnames(
  hostname varchar,
  aid varchar,
  PRIMARY KEY( hostname, aid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE enrollment(
  aid varchar,
  ext_ip varchar,
  int_ip varchar,
  hostname varchar,
  new_org int,
  new_subnet int,
  PRIMARY KEY( aid, ext_ip, int_ip, hostname )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE sensor_reloc(
  aid varchar,
  new_org int,
  new_subnet int,
  PRIMARY KEY( aid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hcp_modules(
  mid int,
  mhash varchar,
  mdat blob,
  msig blob,
  description varchar,
  PRIMARY KEY( mid, mhash )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hcp_module_tasking(
  aid varchar,
  mid int,
  mhash varchar,
  PRIMARY KEY( aid, mid, mhash )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hbs_profiles(
  aid varchar,
  cprofile blob,
  oprofile varchar,
  hprofile varchar,
  PRIMARY KEY( aid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE hbs_queue(
  aid varchar,
  task blob,
  PRIMARY KEY( aid, task )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE events(
  eventid varchar,
  event varchar,
  agentid varchar,
  PRIMARY KEY( eventid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE timeline(
  agentid varchar,
  ts timeuuid,
  eventtype varchar,
  eventid varchar,
  PRIMARY KEY( agentid, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE timeline_by_type(
  agentid varchar,
  ts timeuuid,
  eventtype varchar,
  eventid varchar,
  PRIMARY KEY( agentid, eventtype, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE obj_man
(
  id varchar,

  obj varchar,
  otype int,

  PRIMARY KEY( id )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE obj_name
(
  obj varchar,
  id varchar,
  PRIMARY KEY( obj, id )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc
(
  id varchar,
  aid varchar,

  otype int,
  last timestamp,

  PRIMARY KEY( aid, otype, id )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc_by_id
(
  id varchar,
  aid varchar,
  last timestamp,
  PRIMARY KEY( id, aid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE loc_by_type
(
  d256 int,
  otype int,
  id varchar,
  aid varchar,
  PRIMARY KEY( d256, otype, id, aid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE rel_man_parent
(
  parentkey varchar,
  ctype int,
  cid varchar,
  PRIMARY KEY( parentkey, ctype, cid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;


CREATE TABLE rel_man_child
(
  childkey varchar,
  ptype int,
  pid varchar,
  PRIMARY KEY( childkey, ptype, pid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;


CREATE TABLE recentlyActive
(
  agentid varchar,
  last timestamp,
  PRIMARY KEY( agentid )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE last_events
(
  agentid varchar,
  type varchar,
  id varchar,
  PRIMARY KEY( agentid, type )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE ref_loc
(
  id varchar,
  plat int,
  nloc int,

  PRIMARY KEY( id, plat )
) WITH compaction = { 'class' : 'LeveledCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE detects
(
  did varchar,
  gen timestamp,
  source varchar,
  dtype varchar,
  events varchar,
  detect varchar,

  PRIMARY KEY( did )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE detect_timeline
(
  d int,
  ts timeuuid,
  did varchar,

  PRIMARY KEY( d, ts )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE keyvalue
(
  k varchar,
  c varchar,
  cts timestamp,
  v varchar,

  PRIMARY KEY( k, c )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE atoms_children
(
  atomid uuid,
  child uuid,
  eid varchar,
  PRIMARY KEY( atomid, child )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE atoms_lookup
(
  atomid uuid,
  eid varchar,
  PRIMARY KEY( atomid, eid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE investigation_data
(
  invid varchar,
  ts timeuuid,
  eid varchar,
  etype varchar,
  PRIMARY KEY( invid, ts )
) WITH compaction = { 'class' : 'SizeTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE investigation
(
  invid varchar,
  gen timestamp,
  closed timestamp,
  nature int,
  conclusion int,
  why varchar,

  PRIMARY KEY( invid )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE inv_data
(
  invid varchar,
  gen timeuuid,
  why varchar,
  data blob,

  PRIMARY KEY( invid, gen )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

CREATE TABLE inv_task
(
  invid varchar,
  gen timeuuid,
  why varchar,
  dest varchar,
  data blob,
  sent int,

  PRIMARY KEY( invid, gen )
) WITH compaction = { 'class' : 'DateTieredCompactionStrategy' } AND gc_grace_seconds = 86400;

#! /bin/sh

echo "This wipes the configs in the database, you must restart the cloud for changes to take effect."
echo "DROP KEYSPACE hcp_analytics;" | cqlsh
cqlsh -f ../schema/scale_db.cql

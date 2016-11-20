#! /bin/sh
echo "This wipes the configs in the database, you must restart the cloud for changes to take effect."
echo "use hcp_analytics; truncate hbs_profiles;" | cqlsh
echo "use hcp_analytics; truncate hcp_modules;" | cqlsh
echo "use hcp_analytics; truncate hcp_module_tasking;" | cqlsh


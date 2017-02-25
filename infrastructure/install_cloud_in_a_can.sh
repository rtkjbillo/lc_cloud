#! /bin/sh
export LC_KEY_OPTIONS=--genkeys LC_BRANCH=master LC_SETUP_OPTIONS="-hcp sensor/sample_configs/cloud_in_a_can_hcp.conf -hbs sensor/sample_configs/cloud_in_a_can_hbs.conf"

./bootstrap_cloud_in_a_can.sh

#! /bin/sh

apt-get update -y
apt-get upgrade -y
apt-get install git -y

sudo -c "git clone https://github.com/refractionPOINT/limacharlie.git -b develop &> install_log.txt" `logname`
cd limacharlie/cloud/infrastructure/
python ./1_install_single_node_test_cluster.py &>> install_log.txt
sudo -c "python ./2_start_single_node_test_cluster.py &>> install_log.txt" `logname`
sudo -c "python ./3_configure_single_node_test_cluster.py &>> install_log.txt" `logname`

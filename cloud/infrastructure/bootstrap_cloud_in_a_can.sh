apt-get update -y
apt-get upgrade -y
apt-get install git -y
if [ "$1" == "dev" ]; then
	su -c "git clone --recursive https://github.com/refractionPOINT/limacharlie.git -b develop" `logname`
else
	su -c "git clone --recursive https://github.com/refractionPOINT/limacharlie.git" `logname`
fi
cd limacharlie/cloud/infrastructure/
su -c "touch install_log.txt" `logname`
python ./1_install_single_node_test_cluster.py &>> install_log.txt
su -c "python ./2_start_single_node_test_cluster.py &>> install_log.txt" `logname`
su -c "python ./3_configure_single_node_test_cluster.py -g &>> install_log.txt" `logname`
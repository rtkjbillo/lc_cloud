set -e
apt-get update -y
sleep 1
apt-get upgrade -y
sleep 1
apt-get install python git -y
sleep 1
su -c "git clone --recursive https://github.com/refractionPOINT/limacharlie.git -b $LC_BRANCH" `logname`
cd limacharlie/cloud/infrastructure/
python ./install_cloud_in_a_can.py
su -c "python ./start_cloud_in_a_can.py" `logname`

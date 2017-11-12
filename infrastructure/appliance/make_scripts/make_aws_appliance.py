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

if os.geteuid() != 0:
    print( 'Please run me as root.' )
    sys.exit(-1)

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..', '..' )
originalDir = os.getcwd()
os.chdir( root )

def printStep( step, *ret ):
    msg = '''
===============
Step: %s
Return Values: %s
===============

''' % ( step, str( ret ) )
    print( msg )
    if any( ret ):
        print( 'Stopping execution since this step failed.' )
        sys.exit(-1)

printStep( 'Update initial system packages.',
           os.system( 'yum update -y' ) )

printStep( 'Upgrade max number of file descriptors.',
    os.system( 'echo "* - nofile 102400" >> /etc/security/limits.conf' ),
    os.system( 'echo "root - nofile 102400" >> /etc/security/limits.conf' ),
    os.system( 'echo "session required pam_limits.so" >> /etc/pam.d/common-session' ),
    os.system( 'echo "fs.file-max = 102400" >> /etc/sysctl.conf'),
    os.system( 'sysctl -p' ) )

printStep( 'Initialize hostname.',
           os.system( 'echo "127.0.0.1 `hostname`" >> /etc/hosts' ) )

printStep( 'Install native packages.',
           os.system( 'yum remove java-1.7.0-openjdk -y' ),
           os.system( 'yum install java-1.8.0-openjdk.x86_64 openssl-devel python-pip htop python-m2crypto python-pexpect autoconf libtool git flex byacc bison -y' ) )

printStep( 'Install developer tools.',
           os.system( 'yum groupinstall "Development Tools" -y' ) )

printStep( 'Install pip packages.',
           os.system( 'pip install prefixtree beach time_uuid cassandra-driver virustotal ipaddress tld pyqrcode pypng termcolor slacker slackclient python-dateutil pyOpenSSL pexpect boto3' ) )

printStep( 'Installing Cassandra.',
           os.system( 'echo "[cassandra]" > /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'echo "name=Apache Cassandra" >> /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'echo "baseurl=https://www.apache.org/dist/cassandra/redhat/311x/" >> /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'echo "gpgcheck=1" >> /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'echo "repo_gpgcheck=1" >> /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'echo "gpgkey=https://www.apache.org/dist/cassandra/KEYS" >> /etc/yum.repos.d/cassandra.repo' ),
           os.system( 'yum install cassandra -y' ) )

printStep( 'Initializing Cassandra drive.',
    os.system( 'sleep 30' ),
    os.system( 'service cassandra stop || true' ),
    os.system( 'mkfs.ext4 /dev/xvdb' ),
    os.system( 'mkdir /data' ),
    os.system( 'echo "/dev/xvdb /data ext4 defaults,nofail 0 2" > /etc/fstab' ),
    os.system( 'mount -a' ),
    os.system( 'mkdir /data/cassandra' ),
    os.system( 'chown -R cassandra:cassandra /data' ),
    os.system( 'chmod 700 -R /data' ),
    os.system( 'service cassandra start' ) )

printStep( 'Redirect port 80 and 443 to 9090 so we can run as non-root.',
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9090' ),
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9090' ),
           os.system( 'service iptables save' ) )

printStep( 'Installing Yara.',
    os.system( 'git clone https://github.com/refractionPOINT/yara.git' ),
    os.chdir( 'yara' ),
    os.system( './bootstrap.sh' ),
    os.system( './configure --without-crypto' ),
    os.system( 'make' ),
    os.system( 'make install' ),
    os.chdir( '..' ),
    os.system( 'git clone https://github.com/refractionPOINT/yara-python.git' ),
    os.chdir( 'yara-python' ),
    os.system( 'python setup.py build' ),
    os.system( 'python setup.py install' ),
    os.chdir( '..' ),
    os.system( 'echo "/usr/local/lib" >> /etc/ld.so.conf' ),
    os.system( 'ldconfig' ) )

printStep( 'Create symlink to appliance scripts.',
           os.system( 'ln -s /home/ec2-user/limacharlie/cloud/infrastructure/appliance/*.py /home/ec2-user/' ), )

printStep( 'Preparing Cassandra for new cluster.',
           os.system( 'service cassandra stop || true' ),
           os.system( 'sleep 10' ),
           os.system( 'rm -rf /data/cassandra/data/system' ) )

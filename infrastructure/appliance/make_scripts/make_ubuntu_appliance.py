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

root = os.path.join( os.path.abspath( os.path.dirname( __file__ ) ), '..', '..' )
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
           os.system( 'apt-get update -y' ),
           os.system( 'apt-get upgrade -y' ) )

printStep( 'Upgrade max number of file descriptors.',
    os.system( 'echo "* - nofile 102400" >> /etc/security/limits.conf' ),
    os.system( 'echo "root - nofile 102400" >> /etc/security/limits.conf' ),
    os.system( 'echo "session required pam_limits.so" >> /etc/pam.d/common-session' ),
    os.system( 'echo "fs.file-max = 102400" >> /etc/sysctl.conf'),
    os.system( 'sysctl -p' ) )

printStep( 'Install native packages.',
           os.system( 'apt-get install unzip default-jre-headless openssl python-pip htop python-m2crypto python-pexpect autoconf libtool git flex byacc bison -y' ) )

printStep( 'Install pip packages.',
           os.system( 'pip install markdown time_uuid cassandra-driver virustotal ipaddress tld pyqrcode pypng termcolor slacker slackclient python-dateutil pyOpenSSL pexpect' ) )

print( 'Download prefixtree (expected to fail).' )
os.system( 'pip download prefixtree' )

printStep( 'Installing prefixtree.',
    os.system( 'pip install --upgrade pip' ),
    os.system( 'pip install distribute' ),
    os.system( 'tar xzf *prefixtree*.tar.gz' ),
    os.system( 'rm *prefixtree*.tar.gz' ),
    os.system( 'sed -i \'s/from distribute_setup import use_setuptools//g\' *prefixtree*/setup.py' ),
    os.system( 'sed -i \'s/use_setuptools()//g\' *prefixtree*/setup.py' ),
    os.system( 'cd *prefixtree*; python ./setup.py install; cd ..' ) )

printStep( 'Installing Beach.',
    os.system( 'pip install beach' ) )

printStep( 'Installing Cassandra.',
    os.system( 'echo "deb http://www.apache.org/dist/cassandra/debian 310x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list' ),
    os.system( 'curl https://www.apache.org/dist/cassandra/KEYS | sudo apt-key add -' ),
    os.system( 'apt-get update -y' ) )

os.system( 'apt-get install cassandra -y' )

printStep( 'Initializing Cassandra drive.',
    os.system( 'sleep 30' ),
    os.system( 'service cassandra stop || true' ),
    os.system( 'ls /data || mkdir /data' ),
    os.system( 'mkdir /data/cassandra' ),
    os.system( 'chown -R cassandra:cassandra /data' ),
    os.system( 'chmod 700 -R /data' ),
    os.system( 'service cassandra start' ) )

printStep( 'Redirect port 80 and 443 to 9090 so we can run as non-root.',
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9090' ),
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9090' ),
           os.system( 'iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 9090' ),
           os.system( 'iptables -t nat -A OUTPUT -o lo -p tcp --dport 443 -j REDIRECT --to-port 9090' ),
           os.system( 'echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections' ),
           os.system( 'echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections' ),
           os.system( 'apt-get install iptables-persistent -y' ) )

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
           os.system( 'ln -s /home/server/cloud/infrastructure/appliance/*.py /home/server/' ),
           os.system( 'ln -s /home/server/cloud/beach/hcp/utils /home/server/cloud/limacharlie/' ) )

printStep( 'Preparing Cassandra for new cluster.',
           os.system( 'service cassandra stop || true' ),
           os.system( 'sleep 10' ),
           os.system( 'rm -rf /data/cassandra/data/system' ) )

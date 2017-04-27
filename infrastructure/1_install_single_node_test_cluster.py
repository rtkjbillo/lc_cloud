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
    print( 'Please run me as root to setup this test, but don\'t ever do that in production!' )
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

printStep( 'Upgrade max number of file descriptors.',
           os.system( 'echo "* - nofile 1024000" >> /etc/security/limits.conf' ),
           os.system( 'echo "root - nofile 1024000" >> /etc/security/limits.conf' ),
           os.system( 'echo "session required pam_limits.so" >> /etc/pam.d/common-session' ),
           os.system( 'echo "fs.file-max = 1024000" >> /etc/sysctl.conf'),
           os.system( 'sysctl -p' ) )

printStep( 'Turn off systemd broadcast.',
           os.system( 'echo "ForwardToWall=no" >> /etc/systemd/journald.conf' ),
           os.system( 'systemctl restart systemd-journald' ) )

printStep( 'Updating repo and upgrading existing components.',
    os.system( 'apt-get update -y' ),
    os.system( 'apt-get upgrade -y' ) )

printStep( 'Installing some basic packages required for Beach (mainly).',
    os.system( 'apt-get install openssl python-pip python-dev debconf-utils python-m2crypto python-pexpect autoconf libtool git flex byacc bison unzip -y' ) )

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
    os.system( 'pip install distribute' ),
    os.system( 'pip install beach' ) )

printStep( 'Installing JRE for Cassandra (the hcp-scale-db)',
    os.system( 'apt-get install default-jre-headless -y' ) )

printStep( 'Installing Cassandra.',
    os.system( 'echo "deb http://www.apache.org/dist/cassandra/debian 310x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list' ),
    os.system( 'curl https://www.apache.org/dist/cassandra/KEYS | sudo apt-key add -' ),
    os.system( 'apt-get update -y' ) )

# Ignoring errors here because of a bug in the Ubuntu package.
os.system( 'apt-get install cassandra -y' )

printStep( 'Initializing Cassandra schema.',
    os.system( 'sleep 30' ),
    os.system( 'cqlsh -f %s' % ( os.path.join( root,
                                               'cloud',
                                               'schema',
                                               'scale_db.cql' ), ) ) )

printStep( 'Installing pip packages for various analytics components.',
    os.system( 'pip install time_uuid cassandra-driver virustotal' ),
    os.system( 'pip install ipaddress tld pyqrcode pypng' ),
    os.system( 'pip install slacker slackbot' ) )

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

printStep( 'Setting up host file entries for databases locally.',
    os.system( 'echo "127.0.0.1 hcp-scale-db" >> /etc/hosts' ) )

printStep( 'Setting up the cloud tags.',
    os.system( 'python %s' % ( os.path.join( root,
                                             'tools',
                                             'update_headers.py' ), ) ) )

printStep( 'Setup LC web ui dependencies.',
    os.system( 'ln -s %s %s' % ( os.path.join( root,
                                               'cloud',
                                               'beach',
                                               'hcp',
                                               'utils',
                                               '*' ),
                                 os.path.join( root,
                                               'cloud',
                                               'limacharlie' ) ) ),
    os.system( 'pip install markdown' ) )

printStep( 'Redirect port 80 and 443 to 9090 so we can run as non-root.',
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9090' ),
           os.system( 'iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 9090' ),
           os.system( 'echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections' ),
           os.system( 'echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections' ),
           os.system( 'apt-get install iptables-persistent -y' ) )
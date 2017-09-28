# Copyright 2017 Google Inc
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

import argparse
from hcp.utils.rpcm import rpcm
from hcp.utils.rpcm import rSequence
from hcp.utils.rpcm import rList
from hcp.Symbols import Symbols
from hcp.signing import Signing
import uuid
import base64
from io import BytesIO

_ = Symbols()
rpcm = rpcm()

OBFUSCATION_KEY = "\xFA\x75\x01"

def obfuscate( buffer, key ):
    obf = BytesIO()
    index = 0
    for hx in buffer:
        obf.write( chr( ( ( ord( key[ index % len( key ) ] ) ^ ( index % 255 ) ) ^ ( len( buffer ) % 255 ) ) ^ ord( hx ) ) )
        index = index + 1
    return obf.getvalue()

def urlPort( val ):
    res = val.split( ':' )
    res = ( res[ 0 ], int( res[ 1 ] ) )
    return res

parser = argparse.ArgumentParser( description = 'Create Bootstrap' )
parser.add_argument( '--root_pub_key',
                     type = argparse.FileType( 'r' ),
                     required = True,
                     help = 'root public key to trust in DER format',
                     dest = 'root_pub_key' )
parser.add_argument( '--root_pri_key',
                     type = argparse.FileType( 'r' ),
                     required = True,
                     help = 'root private key to sign store with in DER format',
                     dest = 'root_pri_key' )
parser.add_argument( '--c2_pub_key',
                     type = argparse.FileType( 'r' ),
                     required = True,
                     help = 'c2 public cert to trust',
                     dest = 'c2_pub_cert' )
parser.add_argument( '--primary',
                     type = urlPort,
                     required = True,
                     help = 'primary destination, domain:port',
                     dest = 'primary' )
parser.add_argument( '--secondary',
                     type = urlPort,
                     required = True,
                     help = 'secondary destination, domain:port',
                     dest = 'secondary' )
parser.add_argument( '-o', '--oid',
                     type = uuid.UUID,
                     required = True,
                     help = 'organization id',
                     dest = 'oid' )
parser.add_argument( '-i', '--iid',
                     type = uuid.UUID,
                     required = True,
                     help = 'installer id',
                     dest = 'iid' )
parser.add_argument( '--output_store',
                     type = argparse.FileType( 'w' ),
                     required = True,
                     help = 'output file for store',
                     dest = 'output_store' )
parser.add_argument( '--output_store_sig',
                     type = argparse.FileType( 'w' ),
                     required = True,
                     help = 'output file for store signature',
                     dest = 'output_store_sig' )

arguments = parser.parse_args()

conf = ( rSequence().addStringA( _.hcp.PRIMARY_URL, arguments.primary[ 0 ] )
                    .addInt16( _.hcp.PRIMARY_PORT, arguments.primary[ 1 ] )
                    .addStringA( _.hcp.SECONDARY_URL, arguments.secondary[ 0 ] )
                    .addInt16( _.hcp.SECONDARY_PORT, arguments.secondary[ 1 ] )
                    .addSequence( _.base.HCP_IDENT, rSequence().addBuffer( _.base.HCP_ORG_ID, arguments.oid.bytes )
                                                               .addBuffer( _.base.HCP_INSTALLER_ID, arguments.iid.bytes )
                                                               .addBuffer( _.base.HCP_SENSOR_ID, uuid.UUID( '00000000-0000-0000-0000-000000000000' ).bytes )
                                                               .addInt32( _.base.HCP_PLATFORM, 0 )
                                                               .addInt32( _.base.HCP_ARCHITECTURE, 0 ) )
                    .addBuffer( _.hcp.C2_PUBLIC_KEY, arguments.c2_pub_cert.read() )
                    .addBuffer( _.hcp.ROOT_PUBLIC_KEY, arguments.root_pub_key.read() ) )
conf = rpcm.serialise( conf )
conf = obfuscate( conf, OBFUSCATION_KEY )
confSig = Signing( arguments.root_pri_key.read() ).sign( conf )

arguments.output_store.write( conf )
arguments.output_store_sig.write( confSig )
print( "Enrollment store and signature written to %s and %s." % ( arguments.output_store.name, 
                                                                  arguments.output_store_sig.name ) )
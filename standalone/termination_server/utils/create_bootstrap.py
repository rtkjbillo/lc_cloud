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
from hcp.utils.rpcm import *
from hcp.Symbols import Symbols
import uuid
import base64

_ = Symbols()

parser = argparse.ArgumentParser( description = 'Create Bootstrap' )
parser.add_argument( '--root_pub_key',
                     type = argparse.FileType( 'r' ),
                     required = True,
                     help = 'root public key to trust in DER format',
                     dest = 'root_pub_key' )
parser.add_argument( '--primary',
                     type = lambda x: x.split( ":" ),
                     required = True,
                     help = 'primary destination, domain:port',
                     dest = 'primary' )
parser.add_argument( '--secondary',
                     type = lambda x: x.split( ":" ),
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

arguments = parser.parse_args()

bootstrap = ( rSequence().addStringA( _.hcp.PRIMARY_URL, arguments.primary[ 0 ] )
                         .addInt16( _.hcp.PRIMARY_PORT, arguments.primary[ 1 ] )
                         .addStringA( _.hcp.SECONDARY_URL, arguments.secondary[ 0 ] )
                         .addInt16( _.hcp.SECONDARY_PORT, arguments.secondary[ 1 ] )
                         .addSequence( _.base.HCP_IDENT, rSequence().addBuffer( _.base.HCP_ORG_ID, arguments.oid.bytes )
                                                                    .addBuffer( _.base.HCP_INSTALLER_ID, arguments.iid.bytes )
                                                                    .addBuffer( _.base.HCP_SENSOR_ID, uuid.UUID( '00000000-0000-0000-0000-000000000000' ).bytes )
                                                                    .addInt32( _.base.HCP_PLATFORM, 0 )
                                                                    .addInt32( _.base.HCP_ARCHITECTURE, 0 ) )
                         .addBuffer( _.hcp.ROOT_PUBLIC_KEY, arguments.root_pub_key ) )
bootstrap = base64.b64encode( rpcm().serialise( bootstrap ) )

print( bootstrap )
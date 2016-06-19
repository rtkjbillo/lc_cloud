/*
Copyright 2015 refractionPOINT

Licensed under the Apache License, Version 2.0 ( the "License" );
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "atoms.h"
#include <cryptoLib/cryptoLib.h>

static rBTree g_atoms = NULL;

static RS32
    _compareAtomKeys
    (
        Atom* atom1,
        Atom* atom2
    )
{
    RS32 ret = 0;

    if( NULL != atom1 && NULL != atom2 )
    {
        ret = rpal_memory_memcmp( &(atom1->key), &(atom2->key), sizeof( atom1->key ) );
    }

    return ret;
}

static RVOID
    _freeAtom
    (
        Atom* atom
    )
{
    rpal_memory_zero( atom, sizeof( *atom ) );
}

RBOOL
    atoms_init
    (

    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != ( g_atoms = rpal_btree_create( sizeof( Atom ), _compareAtomKeys, _freeAtom ) ) )
    {
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    atoms_deinit
    (

    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != g_atoms )
    {
        rpal_btree_destroy( g_atoms, FALSE );
        isSuccess = TRUE;
    }

    return isSuccess;
}

RBOOL
    atoms_register
    (
        Atom* pAtom
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pAtom )
    {
        if( CryptoLib_genRandomBytes( pAtom->id, sizeof( pAtom->id ) ) )
        {
            isSuccess = rpal_btree_add( g_atoms, pAtom, FALSE );
            if( !isSuccess )
            {
                if( rpal_btree_remove( g_atoms, pAtom, NULL, FALSE ) )
                {
                    isSuccess = rpal_btree_add( g_atoms, pAtom, FALSE );
                }
            }
        }

        if( !isSuccess )
        {
            rpal_debug_error( "could not register atom" );
        }
    }

    return isSuccess;
}

RBOOL
    atoms_query
    (
        Atom* pAtom
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pAtom )
    {
        isSuccess = rpal_btree_search( g_atoms, pAtom, pAtom, FALSE );
        if( !isSuccess )
        {
            rpal_debug_warning( "atom not found" );
        }
    }

    return isSuccess;
}

RBOOL
    atoms_remove
    (
        Atom* pAtom
    )
{
    RBOOL isSuccess = FALSE;

    if( NULL != pAtom )
    {
        isSuccess = rpal_btree_remove( g_atoms, pAtom, NULL, FALSE );
        if( !isSuccess )
        {
            rpal_debug_error( "atom not found" );
        }
    }

    return isSuccess;
}
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

#define RPAL_FILE_ID 14

#include <rpal_sort_search.h>

#define _ARRAY_ELEM(arr,n,size) ((RPU8)(((RPU8)arr) + ( n * size )))
#define _MOVE_ELEM(dest,arr,n,size) (rpal_memory_memcpy(dest,_ARRAY_ELEM(arr,n,size),size))
#define _SWAP(pElem1,pElem2,size,scratch) rpal_memory_memcpy(scratch,pElem1,size);\
                                          rpal_memory_memcpy(pElem1,pElem2,size);\
                                          rpal_memory_memcpy(pElem2,scratch,size);
#define _KEY_64(pElem) (*(RU64*)(pElem))
#define _KEY_32(pElem) (*(RU32*)(pElem))

static RVOID
    _quicksort
    (
        RPVOID scratch,
        RPVOID pArray,
        RU32 elemSize,
        RU32 iBegin,
        RU32 iEnd
    )
{
    RU32 i = iBegin;
    RU32 j = 0;

    if( iBegin < iEnd )
    {
        _MOVE_ELEM( scratch, pArray, iEnd, elemSize );

        for( j = iBegin; j <= iEnd - 1; j++ )
        {
            if( _KEY_32( _ARRAY_ELEM( pArray, j, elemSize ) ) <= _KEY_32( _ARRAY_ELEM( pArray, iEnd, elemSize ) ) )
            {
                _SWAP( _ARRAY_ELEM( pArray, i, elemSize ),
                       _ARRAY_ELEM( pArray, j, elemSize ),
                       elemSize,
                       scratch );
                i++;
            }
        }
        _SWAP( _ARRAY_ELEM( pArray, i, elemSize ),
               _ARRAY_ELEM( pArray, iEnd, elemSize ),
               elemSize,
               scratch );

        _quicksort( scratch, pArray, elemSize, iBegin, i - 1 );
        _quicksort( scratch, pArray, elemSize, i + 1, iEnd );
    }
}


RBOOL
    rpal_sort_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize
    )
{
    RBOOL isSuccess = FALSE;
    RPVOID tmpElem = NULL;

    if( NULL != pArray )
    {
        if( NULL != ( tmpElem = rpal_memory_alloc( elemSize ) ) )
        {
            _quicksort( tmpElem, pArray, elemSize, 0, nElements - 1 );

            isSuccess = TRUE;

            rpal_memory_free( tmpElem );
        }
    }

    return isSuccess;
}


RU32
    rpal_binsearch_array
    (
        RPVOID pArray,
        RU32 nElements,
        RU32 elemSize,
        RU32 key
    )
{
    RU32 iMin = 0;
    RU32 iMax = nElements;
    RU32 iMid = 0;
    RU32 midKey = 0;

    if( NULL != pArray )
    {
        while( iMin <= iMax )
        {
            iMid = ( ( iMax - iMin ) / 2 ) + iMin;

            midKey = _KEY_32( _ARRAY_ELEM( pArray, iMid, elemSize ) );

            if( midKey == key )
            {
                return iMid;
            }
            else if( midKey < key )
            {
                iMin = iMid + 1;
            }
            else
            {
                iMax = iMid - 1;
            }
        }
    }

    return (RU32)( -1 );
}
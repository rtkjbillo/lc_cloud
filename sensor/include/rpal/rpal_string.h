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

#ifndef _RPAL_STRING_H
#define _RPAL_STRING_H

#include <rpal/rpal.h>

RBOOL 
    rpal_string_isprint 
    (
        RNATIVECHAR ch
    );

RBOOL
    rpal_string_isprintW
    (
        RWCHAR ch
    );

RBOOL
    rpal_string_isprintA
    (
        RCHAR ch
    );

RU8
    rpal_string_str_to_byte
    (
        RNATIVESTR str
    );

RVOID
    rpal_string_byte_to_str
    (
        RU8 b,
        RNATIVECHAR c[ 2 ]
    );

RU32
    rpal_string_strlen
    (
        RNATIVESTR str
    );

RU32
    rpal_string_strlenA
    (
        RPCHAR str
    );

RU32
    rpal_string_strlenW
    (
        RPWCHAR str
    );

RU32
    rpal_string_strsize
    (
        RNATIVESTR str
    );


RU32
    rpal_string_strsizeW
    (
        RPWCHAR str
    );

RU32
    rpal_string_strsizeA
    (
        RPCHAR str
    );

RBOOL
    rpal_string_expandW
    (
        RPWCHAR str,
        RPWCHAR*  outStr
    );

RBOOL
    rpal_string_expandA
    (
        RPCHAR  str,
        RPCHAR*  outStr
    );

RBOOL
    rpal_string_expand
    (
        RNATIVESTR  str,
        RNATIVESTR*  outStr
    );

RPWCHAR
    rpal_string_atow
    (
        RPCHAR str
    );

RPCHAR
    rpal_string_wtoa
    (
        RPWCHAR str
    );

RPWCHAR
    rpal_string_ntow
    (
        RNATIVESTR str
    );

RPCHAR
    rpal_string_ntoa
    (
        RNATIVESTR str
    );

RNATIVESTR
    rpal_string_wton
    (
        RPWCHAR str
    );

RNATIVESTR
    rpal_string_aton
    (
        RPCHAR str
    );

RNATIVESTR
    rpal_string_strcat
    (
        RNATIVESTR str,
        RNATIVESTR toAdd
    );

RNATIVESTR
    rpal_string_strstr
    (
        RNATIVESTR haystack,
        RNATIVESTR needle
    );

RNATIVESTR
    rpal_string_stristr
    (
        RNATIVESTR haystack,
        RNATIVESTR needle
    );

RNATIVESTR
    rpal_string_itos
    (
        RU32 num,
        RNATIVESTR outBuff,
        RU32 radix
    );

RNATIVESTR
    rpal_string_strdup
    (
        RNATIVESTR str
    );

RPWCHAR
    rpal_string_strdupW
    (
        RPWCHAR str
    );

RPCHAR
    rpal_string_strdupA
    (
        RPCHAR str
    );

RBOOL
    rpal_string_match
    (
        RNATIVESTR pattern,
        RNATIVESTR str,
        RBOOL isCaseSensitive
    );

RBOOL
    rpal_string_matchW
    (
        RPWCHAR pattern,
        RPWCHAR str,
        RBOOL isCaseSensitive
    );

RBOOL
    rpal_string_matchA
    (
        RPCHAR pattern,
        RPCHAR str,
        RBOOL isCaseSensitive
    );

RNATIVESTR
    rpal_string_strcatEx
    (
        RNATIVESTR strToExpand,
        RNATIVESTR strToCat
    );

RNATIVESTR
    rpal_string_strtok
    (
        RNATIVESTR str,
        RNATIVECHAR token,
        RNATIVESTR* state
    );

RS32
    rpal_string_strcmp
    (
        RNATIVESTR str1,
        RNATIVESTR str2
    );

RS32
    rpal_string_strcmpW
    (
        RPWCHAR str1,
        RPWCHAR str2
    );

RS32
    rpal_string_strcmpA
    (
        RPCHAR str1,
        RPCHAR str2
    );

RS32
    rpal_string_stricmp
    (
        RNATIVESTR str1,
        RNATIVESTR str2
    );

RNATIVESTR
    rpal_string_toupper
    (
        RNATIVESTR str
    );

RNATIVESTR
    rpal_string_tolower
    (
        RNATIVESTR str
    );

RPWCHAR
    rpal_string_tolowerW
    (
        RPWCHAR str
    );

RPCHAR
    rpal_string_tolowerA
    (
        RPCHAR str
    );

RNATIVESTR
    rpal_string_strcpy
    (
        RNATIVESTR dst,
        RNATIVESTR src
    );

RBOOL
    rpal_string_stoi
    (
        RNATIVESTR str,
        RU32* pNum
    );
    
RBOOL
    rpal_string_fill
    (
        RNATIVESTR str,
        RU32 nChar,
        RNATIVECHAR fillWith
    );
    
RBOOL
    rpal_string_startswith
    (
        RNATIVESTR haystack,
        RNATIVESTR needle
    );
RBOOL
    rpal_string_startswithi
    (
        RNATIVESTR haystack,
        RNATIVESTR needle
    );

RBOOL
    rpal_string_endswith
    (
        RNATIVESTR haystack,
        RNATIVESTR needle
    );

RBOOL
    rpal_string_trim
    (
        RNATIVESTR str,
        RNATIVESTR charsToTrim
    );

RBOOL
    rpal_string_charIsAscii
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsAlphaNum
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsAlpha
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsNum
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsUpper
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsLower
    (
        RNATIVECHAR c
    );

RBOOL
    rpal_string_charIsUpperW
    (
        RWCHAR c
    );

RBOOL
    rpal_string_charIsLowerW
    (
        RWCHAR c
    );

RBOOL
    rpal_string_charIsUpperA
    (
        RCHAR c
    );

RBOOL
    rpal_string_charIsLowerA
    (
        RCHAR c
    );

RNATIVECHAR
    rpal_string_charToUpper
    (
        RNATIVECHAR c
    );

RNATIVECHAR
    rpal_string_charToLower
    (
        RNATIVECHAR c
    );

RWCHAR
    rpal_string_charToUpperW
    (
        RWCHAR c
    );

RWCHAR
    rpal_string_charToLowerW
    (
        RWCHAR c
    );

RCHAR
    rpal_string_charToUpperA
    (
        RCHAR c
    );

RCHAR
    rpal_string_charToLowerA
    (
        RCHAR c
    );

#include <stdio.h>
#define rpal_string_snprintf(outStr,buffLen,format,...) snprintf((outStr),(buffLen),(format),__VA_ARGS__)
#define rpal_string_sscanf(inStr,format,...) sscanf((inStr),(format),__VA_ARGS__)

#define rpal_string_isEmpty(str) (NULL == (str) && 0 == (str)[ 0 ])

#endif

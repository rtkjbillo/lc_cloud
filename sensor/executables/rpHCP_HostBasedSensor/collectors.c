#include "collectors.h"
#include <rpHostCommonPlatformLib/rTags.h>

RBOOL
    hbs_markAsRelated
    (
        rSequence parent,
        rSequence toMark
    )
{
    RBOOL isSuccess = FALSE;
    RPCHAR invId = NULL;

    if( rpal_memory_isValid( parent ) &&
        rpal_memory_isValid( toMark ) )
    {
        isSuccess = TRUE;

        if( rSequence_getSTRINGA( parent, RP_TAGS_HBS_INVESTIGATION_ID, &invId ) )
        {
            isSuccess = FALSE;
            if( rSequence_addSTRINGA( toMark, RP_TAGS_HBS_INVESTIGATION_ID, invId ) )
            {
                isSuccess = TRUE;
            }
        }
    }

    return isSuccess;
}

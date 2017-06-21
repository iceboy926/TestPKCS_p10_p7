//
//  gzdercode.h
//  TestCode
//
//  Created by zuoyongyong on 2017/6/2.
//  Copyright © 2017年 zuoyongyong. All rights reserved.
//

#ifndef gzdercode_h
#define gzdercode_h

#include <stdio.h>
#include "asn1.h"
#include "global_def.h"

DWORD berEncodeSubjectName(BYTE * berSubjectName, DWORD *berSubjectNameLen, BYTE *cndata, DWORD cndata_len, BYTE *odata, DWORD odata_len, BYTE *oudata, DWORD oudata_len, BYTE *cdata, DWORD cdata_len, BYTE *emaildata, DWORD emaildata_len);


#endif /* gzdercode_h */

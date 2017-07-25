//
//  gzdercode.h
//  TestCode
//
//  Created by zuoyongyong on 2017/6/2.
//  Copyright © 2017年 zuoyongyong. All rights reserved.
//

#ifndef pkcs10pack_h
#define pkcs10pack_h

#include <stdio.h>
#include "asn.h"
#include "global_def.h"

DWORD PackPKCS10(BYTE *pubkey, DWORD dwpubkey, BYTE *sign, DWORD dwSignlen, BYTE *berCertReq, DWORD *pdwberCertReqlen);

#endif /* gzdercode_h */

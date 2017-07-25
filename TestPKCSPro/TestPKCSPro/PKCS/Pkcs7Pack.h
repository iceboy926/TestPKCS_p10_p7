//
//  Pkcs7Pack.h

//

#ifndef _Pkcs7Pack_h
#define _Pkcs7Pack_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgndata.h"
#include "platform_type_def.h"
#include "global_def.h"
#include "MyBase64.h"

#ifdef __cplusplus
extern "C" {
#endif

    unsigned long PackPKCS7(unsigned char *plainText, unsigned long plaintTextLen, unsigned char *certData, unsigned long certDataLen, unsigned long nAlgId,unsigned char *signData, unsigned long signDataLen, unsigned char *szOutData, unsigned long *pulOutDataLen);

#ifdef __cplusplus
}
#endif
        
#endif

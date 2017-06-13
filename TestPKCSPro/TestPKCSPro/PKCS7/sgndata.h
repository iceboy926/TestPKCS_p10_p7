#ifndef _SIGN_DATA_H__
#define _SIGN_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sgnerinf.h"
    
#define _max_set_ref	8
#define _overrun_ref	0xd1

//编码
int signData_Encode(unsigned char ** buf, int buflen);
//新增证书
int signData_AddCert(unsigned char * dCert,int  dLen);
//新增签名人
int signData_AddSigner(unsigned char * dCert,int  dLen, int algo, /*文摘算法*/unsigned char * sSign,int  sLen/*签名值*/);
//设置数据
int signData_SetData(unsigned char * dCert,int  dLen);
int signData_GetData(unsigned char * dCert,int  dLen);



#ifdef __cplusplus
}
#endif

#endif


//
//  main.cpp
//  PackCert2P7
//
//  Created by EnterSafe on 15-3-28.
//  Copyright (c) 2015年 test. All rights reserved.
//


#include "Pkcs7Pack.h"




unsigned long PackPKCS7(unsigned char *plainText, unsigned long plaintTextLen, unsigned char *certData, unsigned long certDataLen, unsigned long nAlgId, unsigned char *signData, unsigned long signDataLen, unsigned char *szOutData, unsigned long *pulOutDataLen)
{
    unsigned long uloutData = 0;
    
    int retcode = 0;
    ULONG p7Len = 0;
    unsigned char * pp = NULL;
    int ret = 0;
    
    UINT b64len = 0;
    unsigned int alg_Id = 0;
    
    unsigned char szSignData[1024] = {0};
    unsigned long ulSignDataLen = 0;
    
    unsigned long ulderlen = 0;
    
    switch(nAlgId)
    {
        case M_SHA1:
            alg_Id = digest_sha1_a;
            break;
        case M_SHA256:
            alg_Id = digest_sha256_a;
            break;
        case M_SHA384:
            alg_Id = digest_sha384_a;
            break;
        case M_SHA512:
            alg_Id = digest_sha512_a;
            break;
        case M_SM2:
            alg_Id = digest_sm3_a;
            break;
        case M_MD5:
            alg_Id =digest_md5_a;
            break;
    }
    
    retcode = signData_SetPlainData(plainText, (int)plaintTextLen);
        
    if(retcode <= 0)
    {
        return -1;
    }
    
    if(nAlgId == M_SM2)
    {
        //
        unsigned char Templates[72] = {
            0x30,0x46,0x02,0x21,0x00,
            0x66,0x66,0x28,0x87,0x63,0xCA,0xAC,0xC7,0x9C,0x54,0x37,0x65,0xAB,0xBB,0x52,0x70,
            0x4A,0xCC,0x44,0x8F,0x25,0xA7,0xB3,0x65,0x14,0xDB,0x9F,0x0D,0xB8,0xDE,0x4B,0x2A,
            0x02,0x21,0x00,0xC7,0x82,0x51,0x73,0xB3,0x69,0xB9,0x2E,0x04,0x48,0x87,0x42,0xFB,
            0x83,0x10,0x2A,0x2E,0x61,0xD9,0x7A,0x74,0xD0,0xF1,0x8B,0x3F,0xE2,0x6D,0x2F,0x20,
            0x6D,0xC6,0x85
        };
        memcpy(Templates+5, signData, 0x20);
        memcpy(Templates+40, signData+0x20, 0x20);
        //}
        
        memcpy(szSignData, Templates, sizeof(Templates));
        
        ulSignDataLen = sizeof(Templates);
    }
    else
    {
        //vSign.resize(sigLen);
        //memcpy(&vSign[0], SignData, sigLen);
        memcpy(szSignData, signData, signDataLen);
        ulSignDataLen = signDataLen;
    }

    retcode = signData_AddSigner(certData, (int)certDataLen, alg_Id, szSignData, (int)ulSignDataLen);
    
    unsigned long dwCertEncoded = certDataLen;
    if(retcode <=0)
    {
        return -1;
    }
    
    p7Len = plaintTextLen + dwCertEncoded + ulSignDataLen + 300;
    
    unsigned char p7Buf[2048] = {0};
    pp = &p7Buf[0];
    
    ulderlen = signData_BerEncode(&pp, (int)p7Len);
    
    if(ulderlen <= 0)
    {
        return -1;
    }
    
    
    retcode = myBase64Encode(p7Buf, (int)ulderlen, (char *)szOutData, (unsigned int *)pulOutDataLen);

    return 0;
}


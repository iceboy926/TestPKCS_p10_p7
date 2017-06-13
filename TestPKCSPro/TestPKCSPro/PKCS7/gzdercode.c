//
//  gzdercode.c
//  TestCode
//
//  Created by zuoyongyong on 2017/6/2.
//  Copyright © 2017年 zuoyongyong. All rights reserved.
//

#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include "global_def.h"
#include "gzdercode.h"

DWORD SM2_PubKeyToCFCA_Format
(CHAR* szInput, DWORD dwInputLen, CHAR* szOutput, INT* pdwOutputLen)
{
    SM2PUBLICKEYBLOB* pSM2pubkey = (SM2PUBLICKEYBLOB*)szInput;
    DWORD dwBitLen = pSM2pubkey->BitLen;
    DWORD dwCoordinateLen = dwBitLen/8;
    BYTE* ber_int_x = NULL;
    BYTE* ber_int_y = NULL;
    BYTE* before_seq_buf = NULL;
    DWORD ber_x_len = 0;
    DWORD ber_y_len = 0;
    DWORD ber_seq_len = 0;
    DWORD dwTotalLen = 0;
    DWORD dwRet = ERROR_SUCCESS;
    BYTE *szDataOut = NULL;
    DWORD dwDataOutLen = 0;
    
    //获取x的ber编码长度
    dwRet |= ber_encode_INTEGER
    (TRUE, NULL, &ber_x_len, pSM2pubkey->XCoordinate+SM2_MODULUS_BITS_LEN/8, dwCoordinateLen);
    dwTotalLen += ber_x_len;
    
    //获取y的ber编码长度
    dwRet |= ber_encode_INTEGER
    (TRUE, NULL, &ber_y_len, pSM2pubkey->YCoordinate+SM2_MODULUS_BITS_LEN/8, dwCoordinateLen);
    dwTotalLen += ber_y_len;
    
    //获取seq编码后的长度
    dwRet |= ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, dwTotalLen);
    if ((dwRet != ERROR_SUCCESS) || (ber_seq_len > 1024))
    {
        goto end;
    }
    
    before_seq_buf = (BYTE *)malloc(dwTotalLen);
    dwTotalLen = 0;
    
    //对x编码
    ber_int_x = (BYTE*)malloc(ber_x_len);
    dwRet = ber_encode_INTEGER
    (FALSE, &ber_int_x, &ber_x_len, pSM2pubkey->XCoordinate+SM2_MODULUS_BITS_LEN/8, dwCoordinateLen);
    memcpy(before_seq_buf+dwTotalLen, ber_int_x, ber_x_len);
    dwTotalLen += ber_x_len;
    
    //对y编码
    ber_int_y = (BYTE*)malloc(ber_y_len);
    dwRet = ber_encode_INTEGER
    (FALSE, &ber_int_y, &ber_y_len, pSM2pubkey->YCoordinate+SM2_MODULUS_BITS_LEN/8, dwCoordinateLen);
    memcpy(before_seq_buf+dwTotalLen, ber_int_y, ber_y_len);
    dwTotalLen += ber_y_len;
    
    //对seq编码
    dwRet = ber_encode_SEQUENCE(FALSE, &szDataOut, (DWORD*)&dwDataOutLen, before_seq_buf, dwTotalLen);
    if (dwRet != ERROR_SUCCESS)
    {
        goto end;
    }
    
    *pdwOutputLen = dwDataOutLen;
    
    memcpy(szOutput, szDataOut, dwDataOutLen);
    
end:
    if (ber_int_x)
    {
        free(ber_int_x);
    }
    if (ber_int_y)
    {
        free(ber_int_y);
    }
    if (before_seq_buf)
    {
        free(before_seq_buf);
    }
    
    return dwRet;
}

DWORD SM2_SignDataToCFCA_Format
(CHAR* szInput, DWORD dwInputLen, CHAR* szOutput, INT* pdwOutputLen)
{
    DWORD dwDataFieldLen = 32;
    BYTE* ber_int_r = NULL;
    BYTE* ber_int_s = NULL;
    BYTE* before_seq_buf = NULL;
    DWORD ber_r_len = 0;
    DWORD ber_s_len = 0;
    DWORD ber_seq_len = 0;
    DWORD dwTotalLen = 0;
    DWORD dwOffset = dwDataFieldLen; //0 or 128
    DWORD dwRet = ERROR_SUCCESS;
    
    BYTE *szDataOut = NULL;
    DWORD dwDataOutLen = 0;
    
    //获取r的ber编码长度
    dwRet |= ber_encode_INTEGER
    (TRUE, NULL, &ber_r_len, (BYTE*)szInput, dwDataFieldLen);
    dwTotalLen += ber_r_len;
    
    //获取s的ber编码长度
    dwRet |= ber_encode_INTEGER
    (TRUE, NULL, &ber_s_len, (BYTE*)(szInput + dwOffset), dwDataFieldLen);
    dwTotalLen += ber_s_len;
    
    //获取seq编码后的长度
    dwRet |= ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, dwTotalLen);
    if ((dwRet != ERROR_SUCCESS) || (ber_seq_len > 1024))
    {
        goto end;
    }
    
    before_seq_buf = (BYTE*)malloc(dwTotalLen);
    dwTotalLen = 0;
    
    //对r编码
    ber_int_r = (BYTE*)malloc(ber_r_len);
    dwRet = ber_encode_INTEGER
    (FALSE, &ber_int_r, &ber_r_len, (BYTE*)szInput, dwDataFieldLen);
    if (dwRet != ERROR_SUCCESS)
    {
        goto end;
    }
    memcpy(before_seq_buf+dwTotalLen, ber_int_r, ber_r_len);
    dwTotalLen += ber_r_len;
    
    //对s编码
    ber_int_s = (BYTE*)malloc(ber_s_len);
    dwRet = ber_encode_INTEGER
    (FALSE, &ber_int_s, &ber_s_len, (BYTE*)(szInput + dwOffset), dwDataFieldLen);
    if (dwRet != ERROR_SUCCESS)
    {
        goto end;
    }
    memcpy(before_seq_buf+dwTotalLen, ber_int_s, ber_s_len);
    dwTotalLen += ber_s_len;
    
    //对seq编码
    dwRet = ber_encode_SEQUENCE(FALSE, &szDataOut, &dwDataOutLen, before_seq_buf, dwTotalLen);
    if (dwRet != ERROR_SUCCESS)
    {
        goto end;
    }
    
    *pdwOutputLen = dwDataOutLen;
    memcpy(szOutput, szDataOut, dwDataOutLen);
    
end:
    if (ber_int_r)
    {
        free(ber_int_r);
    }
    if (ber_int_s)
    {
        free(ber_int_s);
    }
    if (before_seq_buf)
    {
        free(before_seq_buf);
    }
    return dwRet;
}

DWORD encodeSubjectName(BYTE ** berSubjectName, DWORD *berSubjectNameLen, BYTE *cndata, DWORD cndata_len, BYTE *odata, DWORD odata_len)
{

    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    BYTE* ber_set_cn = NULL;
    BYTE* ber_set_o = NULL;
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    
    BYTE cn_OIDs[] = {0x55, 0x04, 0x03};
    
    
    //CN_OBJECT_ID
    
    rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, cn_OIDs, sizeof(cn_OIDs));
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }
    else
        len += total;
    
    //CN_OBJECT_ID Value
    rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, cndata, cndata_len);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    //cn sequence
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if ((rc != ERROR_SUCCESS) || (ber_seq_len > 1024))
    {
        goto error;
    }
    
    
    //cn set
    rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, ber_seq_len);
    if ((rc != ERROR_SUCCESS) || (ber_seq_len > 1024))
    {
        goto error;
    }
    
    buf =  (BYTE*)malloc(ber_set_len);
    len = 0;
    
    rc = ber_encode_INTEGER(FALSE, &tmp, &total, cn_OIDs, sizeof(cn_OIDs));
    if (rc != ERROR_SUCCESS)
    {
        //st_err_log(76, __FILE__, __LINE__);
        goto error;
    }
    memcpy(buf + len, tmp, total);
    len += total;
    free(tmp);
    
    rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &total, cndata, cndata_len);
    if (rc != ERROR_SUCCESS)
    {
        //st_err_log(76, __FILE__, __LINE__);
        goto error;
    }
    memcpy(buf + len, tmp, total);
    len += total;
    free(tmp);
    
    
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &total, buf, len);
    if (rc != ERROR_SUCCESS)
        goto error;
    
    memcpy(buf, tmp, total);
    len = total;
    free(tmp);
    
    
    rc = ber_encode_SET(FALSE, &tmp, &total, buf, len);
    if (rc != ERROR_SUCCESS)
        goto error;
    
    memcpy(buf, tmp, total);
    len = total;
    free(tmp);

    
    
    
    
error:
    free(buf);
    return rc;
    
}

/*
--------------------------------------------------------------------
-- Certificate request.
--------------------------------------------------------------------
 
 CertificationRequest ::= SEQUENCE
 {
 certificationRequestInfo   CertificationRequestInfo,
 signatureAlgorithm         AlgorithmIdentifier,
 signature                  BIT STRING
 }
 
 --------------------------------------------
 --  Algorithm Identifier
 --------------------------------------------
 AlgorithmIdentifier ::= SEQUENCE
 {
 algorithm           EncodedObjectID,
 parameters          ANY OPTIONAL
 }
 
 
CertificationRequestInfo ::= SEQUENCE
{
    version                 CertificationRequestInfoVersion,
    subject                 Name,
    subjectPublicKeyInfo    SubjectPublicKeyInfo,
    attributes              [0] IMPLICIT Attributes
}

-------------------------------------------------------
-- Version number.
-------------------------------------------------------
CertificationRequestInfoVersion ::= INTEGER

-------------------------------------------------------
-- Subject distinguished name (DN).
-------------------------------------------------------
Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeValue

AttributeTypeValue ::= SEQUENCE
{
    type               EncodedObjectID,
    value              ANY
}

-------------------------------------------------------
-- Public key information.
-------------------------------------------------------
SubjectPublicKeyInfo ::= SEQUENCE
{
    algorithm           AlgorithmIdentifier,
    subjectPublicKey    BITSTRING
}

-------------------------------------------------------
-- Attributes.
-------------------------------------------------------
Attributes ::= SET OF Attribute

Attribute ::= SEQUENCE
{
    type               EncodedObjectID,
    values             AttributeSetValue
}


*/



/*
PKCS10 Certificate Request:
Version: 1
Subject:
O=TestOrg
CN=TestCN
[0,0]: CERT_RDN_PRINTABLE_STRING, Length = 6 (6/64 Characters)
2.5.4.3 Common Name (CN)="TestCN"

54 65 73 74 43 4e                                  TestCN

54 00 65 00 73 00 74 00  43 00 4e 00               T.e.s.t.C.N.

[1,0]: CERT_RDN_PRINTABLE_STRING, Length = 7 (7/64 Characters)
2.5.4.10 Organization (O)="TestOrg"

54 65 73 74 4f 72 67                               TestOrg

54 00 65 00 73 00 74 00  4f 00 72 00 67 00         T.e.s.t.O.r.g.


Public Key Algorithm:
Algorithm ObjectId: 1.2.840.113549.1.1.1 RSA (RSA_SIGN)
Algorithm Parameters:
05 00
Public Key Length: 1024 bits
Public Key: UnusedBits = 0
0000  30 81 89 02 81 81 00 8f  e2 41 2a 08 e8 51 a8 8c
0010  b3 e8 53 e7 d5 49 50 b3  27 8a 2b cb ea b5 42 73
0020  ea 02 57 cc 65 33 ee 88  20 61 a1 17 56 c1 24 18
0030  e3 a8 08 d3 be d9 31 f3  37 0b 94 b8 cc 43 08 0b
0040  70 24 f7 9c b1 8d 5d d6  6d 82 d0 54 09 84 f8 9f
0050  97 01 75 05 9c 89 d4 d5  c9 1e c9 13 d7 2a 6b 30
0060  91 19 d6 d4 42 e0 c4 9d  7c 92 71 e1 b2 2f 5c 8d
0070  ee f0 f1 17 1e d2 5f 31  5b b1 9c bc 20 55 bf 3a
0080  37 42 45 75 dc 90 65 02  03 01 00 01
Request Attributes: 5
5 attributes:

Attribute[0]: 1.3.6.1.4.1.311.13.2.3 (OS Version)
Value[0][0]:
6.0.5361.2
0000  16 0a 36 2e 30 2e 35 33  36 31 2e 32               ..6.0.5361.2

Attribute[1]: 1.3.6.1.4.1.311.13.2.1 (Enrollment Name Value Pair)
Value[1][0]:
CertificateTemplate=User
0000  30 32 1e 26 00 43 00 65  00 72 00 74 00 69 00 66   02.&.C.e.r.t.i.f
0010  00 69 00 63 00 61 00 74  00 65 00 54 00 65 00 6d   .i.c.a.t.e.T.e.m
0020  00 70 00 6c 00 61 00 74  00 65 1e 08 00 55 00 73   .p.l.a.t.e...U.s
0030  00 65 00 72                                        .e.r

Attribute[2]: 1.3.6.1.4.1.311.21.20 (Client Information)
Value[2][0]:
Unknown Attribute type
Client Id: = 9
(XECI_DISABLE -- 0)
(XECI_XENROLL -- 1)
(XECI_AUTOENROLL -- 2)
(XECI_REQWIZARD -- 3)
(XECI_CERTREQ -- 4)
User: JDOMCSC\administrator
Machine: vich3d.jdomcsc.nttest.microsoft.com
Process: certreq
0000  30 48 02 01 09 0c 23 76  69 63 68 33 64 2e 6a 64   0H....#vich3d.jd
0010  6f 6d 63 73 63 2e 6e 74  74 65 73 74 2e 6d 69 63   omcsc.nttest.mic
0020  72 6f 73 6f 66 74 2e 63  6f 6d 0c 15 4a 44 4f 4d   rosoft.com..JDOM
0030  43 53 43 5c 61 64 6d 69  6e 69 73 74 72 61 74 6f   CSC\administrato
0040  72 0c 07 63 65 72 74 72  65 71                     r..certreq

Attribute[3]: 1.3.6.1.4.1.311.13.2.2 (Enrollment CSP)
Value[3][0]:
Unknown Attribute type
CSP Provider Info
KeySpec = 1
Provider = Microsoft Enhanced Cryptographic Provider v1.0
Signature: UnusedBits=0
0000  30 64 02 01 01 1e 5c 00  4d 00 69 00 63 00 72 00   0d....\.M.i.c.r.
0010  6f 00 73 00 6f 00 66 00  74 00 20 00 45 00 6e 00   o.s.o.f.t. .E.n.
0020  68 00 61 00 6e 00 63 00  65 00 64 00 20 00 43 00   h.a.n.c.e.d. .C.
0030  72 00 79 00 70 00 74 00  6f 00 67 00 72 00 61 00   r.y.p.t.o.g.r.a.
0040  70 00 68 00 69 00 63 00  20 00 50 00 72 00 6f 00   p.h.i.c. .P.r.o.
0050  76 00 69 00 64 00 65 00  72 00 20 00 76 00 31 00   v.i.d.e.r. .v.1.
0060  2e 00 30 03 01 00                                  ..0...

Attribute[4]: 1.2.840.113549.1.9.14 (Certificate Extensions)
Value[4][0]:
Unknown Attribute type
Certificate Extensions: 4
1.3.6.1.4.1.311.20.2: Flags = 0, Length = a
Certificate Template Name (Certificate Type)
User

0000  1e 08 00 55 00 73 00 65  00 72                     ...U.s.e.r

2.5.29.37: Flags = 0, Length = 22
Enhanced Key Usage
Encrypting File System (1.3.6.1.4.1.311.10.3.4)
Secure Email (1.3.6.1.5.5.7.3.4)
Client Authentication (1.3.6.1.5.5.7.3.2)

0000  30 20 06 0a 2b 06 01 04  01 82 37 0a 03 04 06 08   0 ..+.....7.....
0010  2b 06 01 05 05 07 03 04  06 08 2b 06 01 05 05 07   +.........+.....
0020  03 02                                              ..

2.5.29.15: Flags = 1(Critical), Length = 4
Key Usage
Digital Signature, Key Encipherment (a0)

0000  03 02 05 a0                                        ....

2.5.29.14: Flags = 0, Length = 16
Subject Key Identifier
3c 0f 73 da f8 ef 41 d8 3a ea be 92 2a 5d 2c 96 6a 7b 94 54

0000  04 14 3c 0f 73 da f8 ef  41 d8 3a ea be 92 2a 5d   ..<.s...A.:...*]
0010  2c 96 6a 7b 94 54                                  ,.j{.T
    
    0000  30 73 30 17 06 09 2b 06  01 04 01 82 37 14 02 04   0s0...+.....7...
    0010  0a 1e 08 00 55 00 73 00  65 00 72 30 29 06 03 55   ....U.s.e.r0)..U
    0020  1d 25 04 22 30 20 06 0a  2b 06 01 04 01 82 37 0a   .%."0 ..+.....7.
    0030  03 04 06 08 2b 06 01 05  05 07 03 04 06 08 2b 06   ....+.........+.
    0040  01 05 05 07 03 02 30 0e  06 03 55 1d 0f 01 01 ff   ......0...U.....
    0050  04 04 03 02 05 a0 30 1d  06 03 55 1d 0e 04 16 04   ......0...U.....
    0060  14 3c 0f 73 da f8 ef 41  d8 3a ea be 92 2a 5d 2c   .<.s...A.:...*],
    0070  96 6a 7b 94 54                                     .j{.T
        Signature Algorithm:
        Algorithm ObjectId: 1.2.840.113549.1.1.5 sha1RSA
        Algorithm Parameters:
        05 00
    Signature: UnusedBits=0
        0000  1e 6d 8f 05 7b f5 9b 68  72 dd 60 7d e5 f7 fd a0
        0010  20 95 7a 32 88 52 5e 06  0f b4 90 14 51 26 24 eb
        0020  42 87 d5 d4 9e 34 a9 6d  5d 20 0e 76 4b c8 c4 44
        0030  d4 39 0f 46 a1 ba cb a6  99 c7 14 3e a3 eb 9f 55
        0040  c9 5e 11 c7 5e e5 1d 90  94 17 bf fc d0 dd bf 1b
        0050  31 a1 36 66 61 28 b4 c7  ec 25 a5 63 dc cb e3 1f
        0060  97 c4 2b ab 2e 6a b8 0e  66 15 af 24 c6 bf e0 c2
        0070  24 5c 5f c1 32 31 a7 fb  0d 70 9e df 5a 99 eb 47
        Signature matches Public Key
        Key Id Hash(rfc-sha1): 3c 0f 73 da f8 ef 41 d8 3a ea be 92 2a 5d 2c 96 6a 7b 94 54
        Key Id Hash(sha1): ef b9 b3 ba 8d 71 e8 0a a1 c3 54 14 51 5b 73 45 e9 ea 59 a7
    CertUtil: -dump command completed successfully.
*/




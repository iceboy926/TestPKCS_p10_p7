//
//  gzdercode.c
//  TestCode
//
//  Created by zuoyongyong on 2017/6/2.
//  Copyright © 2017年 zuoyongyong. All rights reserved.
//


#include <stdlib.h>
#include <string.h>
#include "gzdercode.h"
#include "sgnerinf.h"



DWORD berEncodeVersion(BYTE *berVersion, DWORD *berVersionLen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    
    BYTE *tmp = NULL;
    
    BYTE version[1] = {0x01};
    int versionlen = sizeof(version);
    
    //获ber编码长度
    rc = ber_encode_INTEGER(TRUE, NULL, &total, version, versionlen);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    rc = ber_encode_INTEGER(FALSE, &tmp, &total, version, versionlen);
    if (rc != ERROR_SUCCESS)
    {
        //st_err_log(76, __FILE__, __LINE__);
        goto error;
    }
    memcpy(berVersion, tmp, total);
    *berVersionLen = total;
    free(tmp);

    
error:
    
    return rc;
}


DWORD berEncodeSubjectName(BYTE * berSubjectName, DWORD *berSubjectNameLen, BYTE *cndata, DWORD cndata_len, BYTE *odata, DWORD odata_len, BYTE *oudata, DWORD oudata_len, BYTE *cdata, DWORD cdata_len, BYTE *ldata, DWORD ldata_len, BYTE *emaildata, DWORD emaildata_len)
{

    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    DWORD cn_total = 0;
    DWORD o_total = 0;
    DWORD ou_total = 0;
    DWORD c_total = 0;
    DWORD l_total = 0;
    DWORD email_total = 0;
    
    BYTE* ber_set_cn = NULL;
    BYTE* ber_set_o = NULL;
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    BYTE cn_OIDs[] = {0x55, 0x04, 0x03}; //XCN_OID_COMMON_NAME (2.5.4.3)
    BYTE o_OIDs[] = {0x55, 0x04, 0x0A}; //XCN_OID_ORGANIZATION_NAME (2.5.4.10)
    BYTE ou_OIDs[] = {0x55, 0x04, 0x0B}; //XCN_OID_ORGANIZATIONAL_UNIT_NAME (2.5.4.11)
    BYTE c_OIDs[] = {0x55, 0x04, 0x06}; //XCN_OID_COUNTRY_NAME
    BYTE l_OIDs[] = {0x55, 0x04, 0x07}; //XCN_OID_LOCALITY_NAME (2.5.4.7)
    BYTE email_OIDs[] = {0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,0x09,0x01}; //XCN_OID_RSA_emailAddr (1.2.840.113549.1.9.1)
    
    
    //CN_OBJECT_ID
    
    if(cndata != NULL)
    {
    
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, cn_OIDs, sizeof(cn_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            goto error;
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
        else
            len = ber_seq_len;
        
        
        //cn set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;
        
        cn_total = len;
    }
    
    if(odata != NULL)
    {
        len = 0;
        total = 0;
        //O_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, o_OIDs, sizeof(o_OIDs));
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //O_OBJECT_VALUE
        rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, odata, odata_len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //O seq
        rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len = ber_seq_len;
        
        //O set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;

        
        o_total = len;
        
    }
    
    if(oudata != NULL)
    {
        len = 0;
        total = 0;
        //OU_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, ou_OIDs, sizeof(ou_OIDs));
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU_OBJECT_VALUE
        rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, oudata, oudata_len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU seq
        rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len = ber_seq_len;
        
        //OU set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;
        
        
        ou_total = len;

    }
    
    if(cdata != NULL)
    {
        len = 0;
        total = 0;
        
        //OU_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, c_OIDs, sizeof(c_OIDs));
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU_OBJECT_VALUE
        rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, cdata, cdata_len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU seq
        rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len = ber_seq_len;
        
        //OU set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;
        
        c_total = len;
    }
    
    if(ldata != NULL)
    {
        len = 0;
        total = 0;
        
        //OU_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, l_OIDs, sizeof(l_OIDs));
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU_OBJECT_VALUE
        rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, ldata, ldata_len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU seq
        rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len = ber_seq_len;
        
        //OU set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;
        
        l_total = len;
    }

    
    
    if(emaildata != NULL)
    {
        len = 0;
        total = 0;
        
        //OU_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, email_OIDs, sizeof(email_OIDs));
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU_OBJECT_VALUE
        rc = ber_encode_PRINTABLE_STRING(TRUE, NULL, &total, emaildata, emaildata_len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len += total;
        
        //OU seq
        rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
        if(rc != ERROR_SUCCESS)
        {
            goto error;
        }
        else
            len = ber_seq_len;
        
        //OU set
        rc = ber_encode_SET(TRUE, NULL, &ber_set_len, NULL, len);
        if ((rc != ERROR_SUCCESS) || (ber_set_len > 1024))
        {
            goto error;
        }
        else
            len = ber_set_len;
        
        email_total = len;
    }
    
    
    len = cn_total + o_total + ou_total + c_total + l_total + email_total;
    
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    len = ber_seq_len;
    
    buf =  (BYTE*)malloc(len);
    
    tempbuf = buf;
    
    if(cndata != NULL)
    {
        len = 0;
        cn_total = 0;
        
        //CN_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &cn_total, cn_OIDs, sizeof(cn_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, cn_total);
        len += cn_total;
        free(tmp);
        
        //CN_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &cn_total, cndata, cndata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, cn_total);
        len += cn_total;
        free(tmp);
        
        
        //CN_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &cn_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, cn_total);
        len = cn_total;
        free(tmp);
        
        
        //CN_SET
        rc = ber_encode_SET(FALSE, &tmp, &cn_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, cn_total);
        len = cn_total;
        free(tmp);
        
        tempbuf += len;
    }

    //
    
    if(odata != NULL)
    {
        len = 0;
        o_total = 0;
        
        //O_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &o_total, o_OIDs, sizeof(o_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, o_total);
        len += o_total;
        free(tmp);
        
        //O_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &o_total, odata, odata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, o_total);
        len += o_total;
        free(tmp);
        
        
        //O_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &o_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, o_total);
        len = o_total;
        free(tmp);
        
        
        //O_SET
        rc = ber_encode_SET(FALSE, &tmp, &o_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, o_total);
        len = o_total;
        free(tmp);
        
        tempbuf += len;

    }
    
    if(oudata != NULL)
    {
        len = 0;
        ou_total = 0;
        
        //O_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &ou_total, ou_OIDs, sizeof(ou_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, ou_total);
        len += ou_total;
        free(tmp);
        
        //O_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &ou_total, oudata, oudata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, ou_total);
        len += ou_total;
        free(tmp);
        
        
        //O_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &ou_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, ou_total);
        len = ou_total;
        free(tmp);
        
        
        //O_SET
        rc = ber_encode_SET(FALSE, &tmp, &ou_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, ou_total);
        len = ou_total;
        free(tmp);
        
        tempbuf += len;
        
    }

    if(cdata != NULL)
    {
        len = 0;
        c_total = 0;
        
        //C_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &c_total, c_OIDs, sizeof(c_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, c_total);
        len += c_total;
        free(tmp);
        
        //C_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &c_total, cdata, cdata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, c_total);
        len += c_total;
        free(tmp);
        
        
        //C_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &c_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, c_total);
        len = c_total;
        free(tmp);
        
        
        //C_SET
        rc = ber_encode_SET(FALSE, &tmp, &c_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, c_total);
        len = c_total;
        free(tmp);
        
        tempbuf += len;
        
    }
    
    if(ldata != NULL)
    {
        len = 0;
        l_total = 0;
        
        //C_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &l_total, l_OIDs, sizeof(l_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, l_total);
        len += l_total;
        free(tmp);
        
        //C_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &l_total, ldata, ldata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, l_total);
        len += l_total;
        free(tmp);
        
        
        //C_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &l_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, l_total);
        len = l_total;
        free(tmp);
        
        
        //C_SET
        rc = ber_encode_SET(FALSE, &tmp, &l_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, l_total);
        len = l_total;
        free(tmp);
        
        tempbuf += len;
        
    }


    if(emaildata != NULL)
    {
        len = 0;
        email_total = 0;
        
        //Email_OBJECT_ID
        rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &email_total, email_OIDs, sizeof(email_OIDs));
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, email_total);
        len += email_total;
        free(tmp);
        
        //Email_OBJECT_Value
        rc = ber_encode_PRINTABLE_STRING(FALSE, &tmp, &email_total, emaildata, emaildata_len);
        if (rc != ERROR_SUCCESS)
        {
            //st_err_log(76, __FILE__, __LINE__);
            goto error;
        }
        memcpy(tempbuf + len, tmp, email_total);
        len += email_total;
        free(tmp);
        
        
        //Email_SEQ
        rc = ber_encode_SEQUENCE(FALSE, &tmp, &email_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, email_total);
        len = email_total;
        free(tmp);
        
        
        //Email_SET
        rc = ber_encode_SET(FALSE, &tmp, &email_total, tempbuf, len);
        if (rc != ERROR_SUCCESS)
            goto error;
        
        memcpy(tempbuf, tmp, email_total);
        len = email_total;
        free(tmp);
        
        tempbuf += len;
    }
    

    //
    len = cn_total + o_total + ou_total + c_total + l_total + email_total;
    
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &ber_seq_len, buf, len);
    if (rc != ERROR_SUCCESS)
        goto error;
    
    *berSubjectNameLen = ber_seq_len;
    
    memcpy(berSubjectName, tmp, ber_seq_len);
    free(tmp);

    
error:
    
    free(buf);
    return rc;
    
}

DWORD berEncodeSubjectPublicKeyInfo(BYTE *berSubjectPubKeyInfo, DWORD *pberSubjectPubKeyInfolen, BYTE *pubkeydata, DWORD pubkeydata_len)
{
    
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    BYTE szHead[1024] = {0x00};
    szHead[0] = 0x00;
    szHead[1] = 0x04;
    
    memcpy(&szHead[2], pubkeydata, pubkeydata_len);
    
    
    
    //alg_oid_length
    
    len = sizeof(_oid_sm2_sign);
    
    rc = ber_encode_BIT_STRING(TRUE, NULL, &total, szHead, pubkeydata_len + 2);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    
    //seq
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len = ber_seq_len;

    
    buf =  (BYTE*)malloc(len);
    if(NULL == buf)
    {
        rc = DC_ERROR_MEMORY_ALLOC;
        goto error;
    }
    
    memset(buf, 0x00, len);
    
    memcpy(buf, _oid_sm2_sign, sizeof(_oid_sm2_sign));
    
    len = sizeof(_oid_sm2_sign);
    total = 0;
    
    rc = ber_encode_BIT_STRING(FALSE, &tmp, &total, szHead, pubkeydata_len + 2);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;


    memcpy(buf + sizeof(_oid_sm2_sign), tmp, total);
    free(tmp);
    
    //seq
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &total, buf, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len = total;
    
    memcpy(buf, tmp, len);
    free(tmp);

    
    *pberSubjectPubKeyInfolen = len;
    
    memcpy(berSubjectPubKeyInfo, buf, len);
    
    
error:
    
    if(buf)
        free(buf);
    return rc;
}

//XCN_OID_KEY_USAGE (2.5.29.15)
/*
typedef enum X509KeyUsageFlags {
    XCN_CERT_NO_KEY_USAGE                 = 0,
    XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE  = 0x80,
    XCN_CERT_NON_REPUDIATION_KEY_USAGE    = 0x40,
    XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE   = 0x20,
    XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE  = 0x10,
    XCN_CERT_KEY_AGREEMENT_KEY_USAGE      = 0x8,
    XCN_CERT_KEY_CERT_SIGN_KEY_USAGE      = 0x4,
    XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE   = 0x2,
    XCN_CERT_CRL_SIGN_KEY_USAGE           = 0x2,
    XCN_CERT_ENCIPHER_ONLY_KEY_USAGE      = 0x1,
    XCN_CERT_DECIPHER_ONLY_KEY_USAGE      = ( 0x80 << 8 )
} X509KeyUsageFlags;
 */
DWORD berAttributeKeyUsage(BYTE *berKeyUsage, DWORD *pberKeyUsage)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_oct_len = 0;
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tmpBuf = NULL;
    
    BYTE keyUsage_OIDs[3] = {0x55, 0x1d, 0x0f};
    
    BYTE keyUsage[] = {0x05, 0xa0}; //XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE | XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
    DWORD dwkeyUsagelen = sizeof(keyUsage);
    
    
    len = 0;
    total = 0;
    //KeyUsage_OBJECT_ID
    rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, keyUsage_OIDs, sizeof(keyUsage_OIDs));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    //
    
    rc = ber_encode_BIT_STRING(TRUE, NULL, &total, keyUsage, dwkeyUsagelen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    rc = ber_encode_OCTET_STRING(TRUE, NULL, &ber_oct_len, NULL, total);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    len += ber_oct_len;
    
    
    
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len = ber_seq_len;
    
    buf = malloc(len * sizeof(BYTE));
    if(buf == NULL)
    {
        rc = DC_ERROR_FUNC_PARAM;
        goto error;
    }
    
    len = 0;
    total = 0;
    
    rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &total, keyUsage_OIDs, sizeof(keyUsage_OIDs));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    memcpy(buf, tmp, len);
    free(tmp);
    
    rc = ber_encode_BIT_STRING(FALSE, &tmp, &total, keyUsage, dwkeyUsagelen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    rc = ber_encode_OCTET_STRING(FALSE, &tmpBuf, &ber_oct_len, tmp, total);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    total = ber_oct_len;
    

    memcpy(buf + len, tmpBuf, total);
    free(tmpBuf);
    free(tmp);
    len += total;
    
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &total, buf, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    memcpy(buf, tmp, total);
    free(tmp);
    
    memcpy(berKeyUsage, buf, total);
    *pberKeyUsage = total;
    
    

error:
    
    if(buf)
        free(buf);
    
    return rc;
    
}

//XCN_OID_SUBJECT_KEY_IDENTIFIER (2.5.29.14)
//Typically the value is a 20-byte SHA-1 hash of the public key contained in the CA signing certificate
DWORD berAttributeSubjectKeyIdentifier(BYTE *berSubjectKeyIdentifier, DWORD *pberSubjectKeyIdentifierlen, BYTE *pubkeyIdentifier, DWORD dwPubKeyIdentifierlen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    BYTE subjectKeyidentifier_oids[3] = {0x55, 0x1d, 0x0e};
    
    
    len = 0;
    total = 0;
    
    rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, subjectKeyidentifier_oids, sizeof(subjectKeyidentifier_oids));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
    {
        len += total;
    }
    
    rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, pubkeyIdentifier, dwPubKeyIdentifierlen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
    {
        ber_set_len = total;
    }
    
    rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, NULL, ber_set_len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
    {
        ber_set_len = total;
    }
    
    len += ber_set_len;
    
    rc = ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    buf = malloc(len *sizeof(BYTE));
    if(buf != NULL)
    {
        rc = DC_ERROR_FUNC_PARAM;
        goto error;
    }
    
    len = 0;
    total = 0;
    
    rc = ber_encode_OBJECT_IDENTIFIER(FALSE, &tmp, &total, subjectKeyidentifier_oids, sizeof(subjectKeyidentifier_oids));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    memcpy(buf, tmp, total);
    len += total;
    free(tmp);
    
    rc = ber_encode_SET(FALSE, &tmp, &total, pubkeyIdentifier, dwPubKeyIdentifierlen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    rc = ber_encode_SET(FALSE, &tempbuf, &ber_set_len, tmp, total);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    memcpy(buf + len, tempbuf, ber_set_len);
    len += ber_set_len;
    free(tmp);
    free(tempbuf);
    
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &ber_seq_len, buf, len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    len = ber_seq_len;
    
    memset(buf, 0, len);
    memcpy(buf, tmp, len);
    free(tmp);
    
    *pberSubjectKeyIdentifierlen = len;
    memcpy(berSubjectKeyIdentifier, buf, len);
    
    
error:
    
    if(buf)
        free(buf);
    
    return rc;
    
}

//XCN_OID_ENHANCED_KEY_USAGE (2.5.29.37)
DWORD berAttributeEnhancedKeyUsage(BYTE *berEnhancedKeyUsage, DWORD *pberEnhancedKeyUsage)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    BYTE enhancedKeyUsage_OIDs[3] = {0x55, 0x1d, 0x25};
    
    len = 0;
    total = 0;
    
    rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, enhancedKeyUsage_OIDs, sizeof(enhancedKeyUsage_OIDs));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    

    
    
    
    
    
error:
    
    return rc;
}

DWORD berCertExtensions(BYTE *berCertExtension, DWORD *pberCertextensionlen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    
    len = 0;
    total = 0;
    
    BYTE certExtensions_OIDs[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e}; //1.2.840.113549.1.9.14
    
    rc = ber_encode_OBJECT_IDENTIFIER(TRUE, NULL, &total, certExtensions_OIDs, sizeof(certExtensions_OIDs));
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    
    
    BYTE berKeyUsage[128] = {0};
    DWORD dwberKeyUsagelen = sizeof(berKeyUsage);
    
    rc = berAttributeKeyUsage(berKeyUsage, &dwberKeyUsagelen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    
    
    
    
error:
    
    if(buf)
    {
        free(buf);
    }
    
    return rc;
}


DWORD berAttribute(BYTE *berAttribute, DWORD *pberAttributelen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    
    
    
  
error:
    
    return rc;
}

DWORD berEncodeCertificationRequestInfo(BYTE *berCerReqInfo, DWORD *pberCerReqInfoLen, BYTE *berVersion, DWORD berVersionlen, BYTE *berSubjectName, DWORD berSubjectNameLen, BYTE *berSubjectPubkeyInfo, DWORD berSubjectPubKeyInfoLen, BYTE *berAttribute, DWORD berAttributeLen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    DWORD ber_set_len = 0;
    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    
    if(NULL == berCerReqInfo || NULL == pberCerReqInfoLen || NULL == berVersion || NULL == berSubjectName
       || NULL == berSubjectPubkeyInfo)
    {
        return DC_ERROR_FUNC_PARAM;
    }
    
    
    len = berVersionlen + berSubjectNameLen + berSubjectPubKeyInfoLen + berAttributeLen;
    
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len = ber_seq_len;
    
    buf = (BYTE *)malloc(len);
    if(buf == NULL)
    {
        rc = DC_ERROR_MEMORY_ALLOC;
        goto error;
    }
    
    memset(buf, 0x00, len);
    
    len = 0;
    memcpy(buf + len, berVersion, berVersionlen);
    len += berVersionlen;
    memcpy(buf + len, berSubjectName, berSubjectNameLen);
    len += berSubjectNameLen;
    memcpy(buf + len, berSubjectPubkeyInfo, berSubjectPubKeyInfoLen);
    len += berSubjectPubKeyInfoLen;
    
    if(NULL != berAttribute && 0 < berAttributeLen)
    {
        memcpy(buf + len, berAttribute, berAttributeLen);
        len += berAttributeLen;
    }
    
    //_SEQ
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &ber_seq_len, buf, len);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    memcpy(berCerReqInfo, tmp, ber_seq_len);
    *pberCerReqInfoLen = ber_seq_len;
    free(tmp);
    
error:
    
    if(buf)
        free(buf);
    return rc;
}

DWORD berEncodeSignAlg(BYTE *berSignAlg, DWORD *pberSignAlglen)
{
    DWORD rc = ERROR_SUCCESS;
    
    *pberSignAlglen = sizeof(_oid_sm2_sm3);
    memcpy(berSignAlg, _oid_sm2_sm3, sizeof(_oid_sm2_sm3));
    
    
    return rc;
}

DWORD berEncodeSignature(BYTE *berSignature, DWORD *pberSignaturelen, BYTE *signdata, DWORD dwSigndatalen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    BYTE *tempbuf = NULL;
    BYTE  tmpsignData[128] = {0};
    DWORD dwtmpsignDatalen = sizeof(tmpsignData);
    
    //03 len 00 r s
    
    char firstByte = signdata[0];
    if((firstByte&0x80) == 0x80)
    {
        dwtmpsignDatalen = dwSigndatalen + 1;
        memcpy(&tmpsignData[1], signdata, dwSigndatalen);
    }
    else
    {
        dwtmpsignDatalen = dwSigndatalen;
        memcpy(&tmpsignData[0], signdata, dwSigndatalen);
    }
    
    rc = ber_encode_BIT_STRING(TRUE, NULL, &total, NULL, dwtmpsignDatalen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    
    buf = malloc(len *sizeof(BYTE));
    if(buf == NULL)
    {
        rc = DC_ERROR_FUNC_PARAM;
        goto error;
    }
    
    len = 0;
    total = 0;
    
    rc = ber_encode_BIT_STRING(FALSE, &tmp, &total, tmpsignData, dwtmpsignDatalen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len += total;
    
    memcpy(buf, tmp, len);
    free(tmp);
    
    *pberSignaturelen = len;
    memcpy(berSignature, buf, len);
    
    
    
error:
    
    if(buf)
    {
        free(buf);
    }
    
    return rc;
}


/*
 
 CertificationRequest ::= SEQUENCE
 {
 certificationRequestInfo   CertificationRequestInfo,
 signatureAlgorithm         AlgorithmIdentifier, sm2_sm3
 signature                  BIT STRING
 }

 
*/

DWORD berEncodeCertReq(BYTE *berCertReq, DWORD *pberCerReqLen, BYTE *berCertReqInfo, DWORD berCertRegInfoLen, BYTE *berAlg, DWORD berAlgLen, BYTE *berSign, DWORD berSignLen)
{
    DWORD total = 0;
    DWORD len = 0; //0 or 128
    DWORD rc = ERROR_SUCCESS;
    DWORD ber_seq_len = 0;

    
    
    BYTE *buf = NULL;
    BYTE *tmp = NULL;
    
    
    if(NULL == berCertReq || pberCerReqLen == NULL || NULL == berCertReqInfo || NULL == berAlg || NULL == berSign)
    {
        return DC_ERROR_FUNC_PARAM;
    }
    
    len = berCertRegInfoLen + berAlgLen + berSignLen;
    
    rc = ber_encode_SEQUENCE(TRUE, NULL, &ber_seq_len, NULL, len);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    else
        len = ber_seq_len;
    
    
    buf = (BYTE *)malloc(len);
    if(NULL == buf)
    {
        rc = DC_ERROR_FUNC_PARAM;
        goto error;
    }
    
    memset(buf, 0x00, len);
    
    len = 0;
    
    memcpy(buf, berCertReqInfo, berCertRegInfoLen);
    len += berCertRegInfoLen;
    memcpy(buf + len, berAlg, berAlgLen);
    len += berAlgLen;
    memcpy(buf + len, berSign, berSignLen);
    len += berSignLen;
    
    
    rc = ber_encode_SEQUENCE(FALSE, &tmp, &ber_seq_len, buf, len);
    if (rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    memcpy(berCertReq, tmp, ber_seq_len);
    *pberCerReqLen = ber_seq_len;
    free(tmp);
    
    

    
error:
    
    if(buf)
        free(buf);
    return rc;
}



DWORD PackPKCS10(BYTE *pubkey, DWORD dwpubkey, BYTE *sign, DWORD dwSignlen, BYTE *berCertReq, DWORD *pdwberCertReqlen)
{

    DWORD rc = ERROR_SUCCESS;
    
    BYTE berVersion[64] = {0};
    DWORD dwberVersionLen = sizeof(berVersion);
    
    rc = berEncodeVersion(berVersion, &dwberVersionLen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    BYTE berSubjectName[1024] = {0};
    DWORD dwberSubjectNameLen = sizeof(berSubjectName);
    
    BYTE cndata[] = "zuoyy";
    DWORD cndata_len = strlen(cndata);
    
    BYTE odata[] = "testorg";
    DWORD odata_len = strlen(odata);
    
    BYTE oudata[] = "testorgunit";
    DWORD oudata_len = strlen(oudata);
    
    BYTE cdata[] = "cn";
    DWORD cdata_len = strlen(cdata);
    
    BYTE emaildata[] = "zuoyy@gmrz-bj.com";
    DWORD emaildata_len = strlen(emaildata);
    
    BYTE ldata[] = "bj";
    DWORD ldata_len = strlen(ldata);
    
    
    
    rc = berEncodeSubjectName(berSubjectName, &dwberSubjectNameLen, cndata, cndata_len, odata, odata_len, oudata, oudata_len, cdata, cdata_len, ldata, ldata_len, emaildata, emaildata_len);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    BYTE berSubjectPubKeyInfo[1024] = {0x00};
    DWORD dwberSubjectPubKeyInfolen = sizeof(berSubjectPubKeyInfo);
  
    rc = berEncodeSubjectPublicKeyInfo(berSubjectPubKeyInfo, &dwberSubjectPubKeyInfolen, pubkey, dwpubkey);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    BYTE berCertRequestInfo[1024] = {0};
    DWORD dwberCertRequestInfolen = sizeof(berCertRequestInfo);
    
    rc = berEncodeCertificationRequestInfo(berCertRequestInfo, &dwberCertRequestInfolen, berVersion, dwberVersionLen, berSubjectName, dwberSubjectNameLen, berSubjectPubKeyInfo, dwberSubjectPubKeyInfolen, NULL, 0);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    BYTE berSignAlg[128] = {0};
    DWORD dwberSignAlglen = sizeof(berSignAlg);
    
    rc = berEncodeSignAlg(berSignAlg, &dwberSignAlglen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    BYTE berSign[128] = {0};
    DWORD dwberSignlen = sizeof(berSign);
    
    
    rc = berEncodeSignature(berSign, &dwberSignlen, sign, dwSignlen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    rc = berEncodeCertReq(berCertReq, pdwberCertReqlen, berCertRequestInfo, dwberCertRequestInfolen, berSignAlg, dwberSignAlglen, berSign, dwberSignlen);
    if(rc != ERROR_SUCCESS)
    {
        goto error;
    }
    
    
    rc = 0;
    
error:
    
    return rc;
}




/*
 CertificationRequestInfo ::= SEQUENCE {
 version        	INTEGER { v1(0) } (v1,...),
 subject        	Name,
 subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 attributes     	[0] Attributes{{ CRIAttributes }}
 }
 SubjectPublicKeyInfo {ALGORITHM: IOSet} ::= SEQUENCE {
 algorithm			AlgorithmIdentifier {{IOSet}},
 subjectPublicKey 	BIT STRING
 }
 PKInfoAlgorithms ALGORITHM ::= { ... -- add any locally defined algorithms here -- }
 Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 
 CRIAttributes  ATTRIBUTE  ::= { ... -- add any locally defined attributes here -- }
 Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 type   	ATTRIBUTE.&id({IOSet}),
 values 	SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 }
 CertificationRequest ::= SEQUENCE {
 certificationRequestInfo	CertificationRequestInfo,
 signatureAlgorithm		AlgorithmIdentifier{{ SignatureAlgorithms }},
 signature                 		BIT STRING
 }
 AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
 algorithm   	ALGORITHM.&id({IOSet}),
 parameters  	ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 }
 SignatureAlgorithms ALGORITHM ::= { ... -- add any locally defined algorithms here -- }
 
 */


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




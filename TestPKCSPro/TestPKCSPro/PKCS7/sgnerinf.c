#include "sgnerinf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int signInfo_digestAlgo = 0;//
unsigned char* psignInfoSigned = 0;
int signInfoSignLen = 0;

//
int signerInfo_SetCert(unsigned char * dCert,int  dLen)
{
	return signerCert_SetCert(dCert,dLen);
}

int signerInfo_GetCertLen()
{
    return signerCert_GetCertlen();
}

//
int signerInfo_GetDigestAlgo(void)
{
	return signInfo_digestAlgo;
}

int signerInfo_SetDigestAlgo(int algo)
{
	if(algo == digest_md5_a ||
	   algo == digest_sha1_a ||
	   algo == digest_sha256_a ||
	   algo == digest_sha384_a ||
	   algo == digest_sha512_a ||
	   algo == digest_sm3_a
		)
		signInfo_digestAlgo = algo;
	else
		return 0;

	return algo;
}

int signerInfo_SetSigned(unsigned char * sSign,int  sLen)
{
	int ret = 0;
	if(sSign == NULL){
		return -_signer_io_;
	}
	if(psignInfoSigned){
		free(psignInfoSigned);
		psignInfoSigned =0;signInfoSignLen = 0;
	}
	psignInfoSigned = (unsigned char*)malloc(sLen+1);
	if(psignInfoSigned == NULL){
		return -_signer_memory_;
	}

	memcpy(psignInfoSigned,sSign,sLen);
	signInfoSignLen = sLen;
	ret = signInfoSignLen;
	return ret;
}

int signerInfo_GetSigned(unsigned char * sSign,int  sLen)
{
	int ret = 0;

	if(psignInfoSigned == NULL){
		return -_signer_memory_;
	}
	if(sLen< signInfoSignLen){
		return -_signer_io_;
	}

	if(sSign == NULL){
		return -_signer_io_;
	}

	memcpy(sSign, psignInfoSigned,signInfoSignLen);
	ret = signInfoSignLen;
	return ret;
}
// SignerInfo ::= SEQUENCE {
// 		version Version,
// 		issuerAndSerialNumber	IssuerAndSerialNumber,
// 		digestAlgorithm			DigestAlgorithmIdentifier,

// 		authenticatedAttributes
// 		[0] IMPLICIT Attributes OPTIONAL,
// 		digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier
//
// 		encryptedDigest EncryptedDigest,

// 		unauthenticatedAttributes
// 		[1] IMPLICIT Attributes OPTIONAL }
// EncryptedDigest ::= OCTET STRING

int  signerInfo_adjustLen(  int inputLen)
{
	unsigned char _code[1024] = {0,};
	int ret = 0;
	//int contentLen = 3;/*02 01 01*/
	int i = inputLen;

	i  = inputLen-3;

	ret = signerCert_GetID( _code,1024);
	if(ret<=0){
		return ret;
	}

	ret = signerCert_adjustLen( ret,i );
	if(ret<=0){
		return ret;
	}

	i -=ret;

	ret = signerInfo_GetDigestAlgo();
	if(ret<=0)
		return -_signer_algo_;

	switch(ret){
	case digest_md5_a:
		i-= (strlen((char*)_oid_md5)+1);
		break;
	case digest_sha1_a:
		i-= (strlen((char*)_oid_sha1)+1);
		break;
	case digest_sha256_a:
		i-= (strlen((char*)_oid_sha256)+1);
		break;
	case digest_sha384_a:
		i-= (strlen((char*)_oid_sha384)+1);
		break;
	case digest_sha512_a:
		i-= (strlen((char*)_oid_sha512)+1);
		break;
	case digest_sm3_a:
		i-= (strlen((char*)_oid_sm3)+1);
		break;
	default:
		return -_signer_algo_;
	}

	if(i<=0){
		return -_signer_algo_;

	}
	if (digest_sm3_a == ret)
		i-=(strlen((char*)_oid_sm2_sign)+1);
	else
		i-=(strlen((char*)_oid_rsaEncrypt)+1);
	if(i<=0){
		return -_signer_algo_;

	}

	if(psignInfoSigned == NULL){
		return -_signer_io_;
	}
	if( signInfoSignLen <= 0){
		return -_signer_io_;
	}

	ret = signerCert_adjustLen( signInfoSignLen,i );
	if(ret<=0){
		return ret;
	}

	i-=ret;

	ret = inputLen-i;

	return ret;
}

/*
SignerInfo ::= SEQUENCE {
    version Version,
    issuerAndSerialNumber      IssuerAndSerialNumber,
    digestAlgorithm            DigestAlgorithmIdentifier,
        authenticatedAttributes    [0] IMPLICIT Attributes OPTIONAL,
    digestEncryptionAlgorithm  DigestEncryptionAlgorithmIdentifier,
    encryptedDigest             EncryptedDigest,
        unauthenticatedAttributes  [1] IMPLICIT Attributes OPTIONAL }
*/

int signerInfo_BerEncode(unsigned char ** buf, int buflen)
{
	int ret = 0;
	int i=0;
    int decrease=0;
    int adjust=0;
	adjust = signerInfo_adjustLen( buflen);
	if(adjust<=0)
		return adjust;

	i =adjust;
	ret = signerCert_adjustLen( adjust, buflen);
	if( ret<=0){
		return ret;
	}
    
    //SEQUENCE OF
	decrease = buflen;
	*(*buf) = 0x30;
	(*buf)++;
	decrease--;

	if(ret-i == 2){
		*(*buf) = i;
		(*buf)++;
		decrease--;
	}
	else if(ret-i == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = i;
		(*buf)++;
		decrease--;
	}
	else if(ret-i == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;

		*(*buf) = (i>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (i);
		(*buf)++;
		decrease--;
	}

    //version
	*(*buf) = 0x02;
	(*buf)++;
	decrease--;
	*(*buf) = 0x01;
	(*buf)++;
	decrease--;
	*(*buf) = 0x01;
	(*buf)++;
	decrease--;

    
    //IssuerAndSerialNumber
	ret = signerCert_Encode_SerialNumber( buf,decrease);
	decrease-=ret;

    
    //DigestAlgorithmIdentifier
	ret = signerInfo_GetDigestAlgo();
	if(ret<=0)
		return -_signer_algo_;

	switch(ret)
    {
        case digest_md5_a:
            {
                i= (strlen((char *)_oid_md5)+1);
                memcpy((*buf),_oid_md5,i  );
                (*buf)+=i;
                decrease-=i;
            }

            break;
        case digest_sha1_a:
            {
                i= (strlen((char*)_oid_sha1)+1);
                memcpy((*buf),_oid_sha1,i  );
                (*buf)+=i;
                decrease-=i;
            }
            break;
        case digest_sha256_a:
            {
                i= (strlen((char*)_oid_sha256)+1);
                memcpy((*buf),_oid_sha256,i  );
                (*buf)+=i;
                decrease-=i;
            }
            break;
        case digest_sha384_a:
            {
                i = (strlen((char*)_oid_sha384)+1);
                memcpy((*buf), _oid_sha384, i);
                (*buf) += i;
                decrease -= i;
            }
            break;
        case digest_sha512_a:
            {
                i = (strlen((char*)_oid_sha512)+1);
                memcpy((*buf), _oid_sha512, i);
                (*buf) += i;
                decrease -= i;
            }
            break;
        case digest_sm3_a:
            {
                i = (strlen((char*)_oid_sm3)+1);
                memcpy((*buf), _oid_sm3, i);
                (*buf) += i;
                decrease -= i;
            }
            break;
        default:
            return -_signer_algo_;
	}

    //DigestEncryptionAlgorithmIdentifier
    if(digest_sm3_a == ret)
    {
        i= (strlen((char*)_oid_sm2_sign)+1);
        memcpy((*buf),_oid_sm2_sign,i  );
    }
    else
    {
        i= (strlen((char*)_oid_rsaEncrypt)+1);
        memcpy((*buf),_oid_rsaEncrypt,i  );
    }
    (*buf)+=i;
    decrease-=i;

    //EncryptedDigest
    ret = signerCert_adjustLen( signInfoSignLen, decrease);
    if( ret<=0){
        return ret;
    }

    *(*buf) = 0x04;
    (*buf)++;
    decrease--;

    if(ret-signInfoSignLen == 2){
        *(*buf) = signInfoSignLen;
        (*buf)++;
        decrease--;
    }
    else if(ret-signInfoSignLen == 3){
        *(*buf) = 0x81;
        (*buf)++;
        decrease--;
        *(*buf) = signInfoSignLen;
        (*buf)++;
        decrease--;
    }
    else if(ret-signInfoSignLen == 4){
        *(*buf) = 0x82;
        (*buf)++;
        decrease--;

        *(*buf) = (signInfoSignLen>>8);
        (*buf)++;
        decrease--;

        *(*buf) = (signInfoSignLen);
        (*buf)++;
        decrease--;
    }

    i= signInfoSignLen;
    memcpy((*buf),psignInfoSigned,i  );
    (*buf)+=i;
    decrease-=i;


	ret = buflen-decrease;

	if(ret!= signerCert_adjustLen( adjust, buflen))
	{
		return -_signer_encode_;
	}
	return ret;
}

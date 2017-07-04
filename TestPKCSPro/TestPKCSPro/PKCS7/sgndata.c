#include "sgndata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static unsigned char signedheader[12]= {
    0x06,0x09,0x2A,0x86,0x48,
    0x86,0xF7,0x0D,0x01,0x07,
    0x02,0x00};   //1.2.840.113549.1.7.2 pkcs-7-2 signdata oid
static unsigned char datadheader[12]= {
    0x06,0x09,0x2A,0x86,0x48,
    0x86,0xF7,0x0D,0x01,0x07,
    0x01,0x00};  //1.2.840.113549.1.7.1  pkcs-7-1 data oid



int signCertcertLen = 0;
int signCertsignerLen = 0;

//签名的原文
unsigned char* signCertpData = 0;
int signCertdataLen = 0;

int _EncodeSetSigner(unsigned char ** buf, int buflen);
int _EncodeSetCerts(unsigned char ** buf, int buflen);
int _EncodeData(unsigned char ** buf, int buflen);
int _EncodeSetDigests(unsigned char ** buf, int buflen);


//新增签名人
int signData_AddSigner(unsigned char * dCert,int  dLen,int algo,unsigned char * sSign,int  sLen)
{
	int ret=0;
    
    signCertsignerLen = 0;

	if(signCertsignerLen>=_max_set_ref){
		return -_overrun_ref;
	}

	ret = signerInfo_SetCert(dCert,dLen);
	if(ret<=0)
	{
		return ret;
	}
	ret = signerInfo_SetDigestAlgo(algo);
	if(ret<=0)
	{
		return ret;
	}
	ret = signerInfo_SetSigned(sSign,sLen);
	if(ret<=0)
	{
		return ret;
	}

	signCertsignerLen++;
	ret = signCertsignerLen;
	return ret;
}
////新增证书
//int signData_AddCert(unsigned char * dCert,int  dLen)
//{
//	int ret=0;
//	
//	if(signCertcertLen>=_max_set_ref){
//		return -_overrun_ref;
//	}
//	
//	ret = signerCert_SetCert(dCert,dLen);
//	if(ret<=0)
//	{
//		return ret;
//	}
//	signCertcertLen++;
//	ret = signCertcertLen;
//	return ret;
//}



//设置数据
int signData_SetPlainData(unsigned char * dCert,int  dLen)
{
	int ret = 0;
	if(dCert == NULL){
		return -_signer_io_;
	}
	if(signCertpData){
		free(signCertpData);
		signCertpData =0;signCertdataLen = 0;
	}
	signCertpData = (unsigned char*)malloc(dLen+1);
	if(signCertpData == NULL){
		return -_signer_memory_;
	}
	
	memcpy(signCertpData,dCert,dLen);
	signCertdataLen = dLen;
	ret = signCertdataLen;
	return ret;
}
//
//int signData_GetPlainData(unsigned char *dCert,int  dLen)
//{
//	int ret = 0;
//	
//	if(signCertpData == NULL){
//		return -_signer_memory_;
//	}
//	if(dLen< signCertdataLen){
//		return -_signer_io_;
//	}
//	
//	if(dCert == NULL){
//		return -_signer_io_;
//	}
//	
//	memcpy(dCert, signCertpData,signCertdataLen);
//	ret = signCertdataLen;
//	return ret;
//}

//

int _EncodeSetSigner(unsigned char ** buf, int buflen)
{
	int ret=0;
	int a=0;int l = buflen;

	int i;
	for(i=0;i<signCertsignerLen;i++)
	{
		ret = signerInfo_adjustLen(l);
		if(ret<=0){
			return ret;
		}
		a+=ret;
		l-=ret;
	}

	ret = signerCert_adjustLen( a,buflen );
	if(ret<=0){
		return ret;
	}
	a = ret;
	ret = signerCert_adjustLen( a,buflen );
	if(ret<=0){
		return ret;
	}


	int decrease = buflen;
	*(*buf) = 0x31; 
	(*buf)++;
	decrease--;
	
	if(ret- a == 2){
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	
	for(i=0;i<signCertsignerLen;i++)
	{
		ret = signerInfo_BerEncode( buf, decrease);
		if(ret<=0){
			return ret;
		}
		decrease-=ret;
	}
	
	ret = buflen-decrease;
	
	if(ret!= signerCert_adjustLen( a, buflen))
	{
		return -_signer_encode_;
	}


	return ret;
}

int _EncodeSetDigests(unsigned char ** buf, int buflen)
{
	int ret=0;
	int a=0;int l = buflen;
	int flag=0;	
	int i;
	for(i=0;i<signCertsignerLen;i++)
	{
		ret = signerInfo_GetDigestAlgo();
		if(ret<=0){
			return ret;
		}

		switch( ret)
		{
		case digest_md5_a:
			if((flag & digest_md5_a )==0)
			{
				a+= (strlen( (char*)_oid_md5)+1);
				flag|=digest_md5_a;
			}
			break;
		case digest_sha1_a:
			if((flag & digest_sha1_a )==0)
			{
			a+= (strlen( (char*)_oid_sha1)+1);
			flag|=digest_sha1_a;
			}
			break;
		case digest_sha256_a:
			if((flag & digest_sha256_a )==0)
			{
			a+= (strlen( (char*)_oid_sha256)+1);
			flag|=digest_sha256_a;
			}
			break;
		case digest_sha384_a:
			if((flag & digest_sha384_a) == 0)
			{
				a += (strlen((char*)_oid_sha384)+1);
				flag |= digest_sha384_a;
			}
			break;
		case digest_sha512_a:
			if((flag & digest_sha512_a) == 0)
			{
				a += (strlen((char*)_oid_sha512)+1);
				flag |= digest_sha512_a;
			}
			break;
		case digest_sm3_a:
			if((flag & digest_sm3_a) == 0)
			{
				a += (strlen((char*)_oid_sm3)+1);
				flag |= digest_sm3_a;
			}
			break;
		}
	}
	
	ret = signerCert_adjustLen( a,buflen );
	if(ret<=0){
		return ret;
	}
	
	
	int decrease = buflen;
	*(*buf) = 0x31; 
	(*buf)++;
	decrease--;
	
	if(ret- a == 2){
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}

	flag=0;	
	for(i=0;i<signCertsignerLen;i++)
	{
		ret = signerInfo_GetDigestAlgo();
		if(ret<=0){
			return ret;
		}
		
		switch( ret)
		{
		case digest_md5_a:
			if((flag & digest_md5_a )==0)
			{
				l = (strlen( (char*)_oid_md5)+1) ;
				memcpy((*buf),_oid_md5,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_md5_a;
			}
			break;
		case digest_sha1_a:
			if((flag & digest_sha1_a )==0)
			{
				l = (strlen( (char*)_oid_sha1)+1) ;
				memcpy((*buf),_oid_sha1,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_sha1_a;
			}
			break;
		case digest_sha256_a:
			if((flag & digest_sha256_a )==0)
			{
				l = (strlen( (char*)_oid_sha256)+1) ;
				memcpy((*buf),_oid_sha256,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_sha256_a;
			}
			break;
		case digest_sha384_a:
			if((flag & digest_sha384_a )==0)
			{
				l = (strlen( (char*)_oid_sha384)+1) ;
				memcpy((*buf),_oid_sha384,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_sha384_a;
			}
			break;
		case digest_sha512_a:
			if((flag & digest_sha512_a )==0)
			{
				l = (strlen( (char*)_oid_sha512)+1) ;
				memcpy((*buf),_oid_sha512,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_sha512_a;
			}
			break;
		case digest_sm3_a:
			if((flag & digest_sm3_a )==0)
			{
				l = (strlen( (char*)_oid_sm3)+1) ;
				memcpy((*buf),_oid_sm3,l);
				(*buf)+=l;
				decrease-=l;

				flag|=digest_sm3_a;
			}
			break;
		}
	}
	
	
	ret = buflen-decrease;
	
	if(ret!= signerCert_adjustLen( a, buflen))
	{
		return -_signer_encode_;
	}
	
	
	return ret;

}

int _EncodeSetCerts(unsigned char ** buf, int buflen)
{
	int ret=0;
	int a=0;int l = buflen;
	
	int i;
	for(i=0;i<signCertcertLen;i++)
	{
		a+=signerCert_GetCertlen();
		l-=signerCert_GetCertlen();
	}

	for(i=0;i<signCertsignerLen;i++)
	{
		a+=signerInfo_GetCertLen();
		l-=signerInfo_GetCertLen();
	}

	ret = signerCert_adjustLen( a,buflen );
	if(ret<=0){
		return ret;
	}
	
	
	int decrease = buflen;
	*(*buf) = 0xA0; 
	(*buf)++;
	decrease--;
	
	if(ret- a == 2){
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}


	for(i=0;i<signCertcertLen;i++)
	{
		l = signerCert_GetCertlen() ;
        
        unsigned char *tempCert = (unsigned char *)malloc(2048);
        signerCert_GetCert(tempCert, 2048);
		memcpy((*buf),tempCert,l);
		(*buf)+=l;
		decrease-=l;
        if(tempCert)
        {
            free(tempCert);
            tempCert = NULL;
        }

	}

	for(i=0;i<signCertsignerLen;i++)
	{
		//l = _signers[i]._cert.certLen ;
		//memcpy((*buf),_signers[i]._cert.pCert,l);
        l = signerCert_GetCertlen() ;
        
        unsigned char *tempCert = (unsigned char *)malloc(2048);
        signerCert_GetCert(tempCert, 2048);
        memcpy((*buf),tempCert,l);
        
		(*buf)+=l;
		decrease-=l;
        if(tempCert)
        {
            free(tempCert);
            tempCert = NULL;
        }
	}
	
	ret = buflen-decrease;
	
	if(ret!= signerCert_adjustLen( a, buflen))
	{
		return -_signer_encode_;
	}
	
	
	return ret;

}


int _EncodeData(unsigned char ** buf, int buflen)
{
	int ret=0;
	int a=0;int l = buflen;

	if(signCertdataLen>0 && signCertpData){
		a = signCertdataLen;

		ret = signerCert_adjustLen( a,buflen );
		if(ret<=0){
			return ret;
		}
		/*04 xx*/
		a=ret;
		ret = signerCert_adjustLen( a,buflen );
		if(ret<=0){
			return ret;
		}
		/*a0 xx*/
		a= ret;
		a+= strlen((char*)datadheader);

		ret = signerCert_adjustLen( a,buflen );
		if(ret<=0){
			return ret;
		}
	}
	else
	{
		a=0;
		a+= strlen((char*)datadheader);
		a+=2;/*a0 00*/
		ret = signerCert_adjustLen( a,buflen );
		if(ret<=0){
			return ret;
		}

	}
	
	
	int decrease = buflen;
	*(*buf) = 0x30; 
	(*buf)++;
	decrease--;
	
	if(ret- a == 2){
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 5){
		*(*buf) = 0x83;
		(*buf)++;
		decrease--;

		*(*buf) = (a>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 6){
		*(*buf) = 0x84;
		(*buf)++;
		decrease--;

		*(*buf) = (a>>24);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	//赋值
	
	l = strlen((char*)datadheader);
	memcpy((*buf),datadheader,l);
	(*buf)+=l;
	decrease-=l;
		
	if(signCertdataLen>0 && signCertpData){

		l = signerCert_adjustLen( signCertdataLen,decrease );
		if(l<=0){
			return l;
		}
		ret = signerCert_adjustLen( l,decrease );
		if(ret<=0){
			return ret;
		}

		*(*buf) = 0xA0; 
		(*buf)++;
		decrease--;
		
		if(ret- l == 2){
			*(*buf) = l;
			(*buf)++;
			decrease--;
		}
		else if(ret-l == 3){
			*(*buf) = 0x81;
			(*buf)++;
			decrease--;
			*(*buf) = l;
			(*buf)++;
			decrease--;
		}
		else if(ret-l == 4){
			*(*buf) = 0x82;
			(*buf)++;
			decrease--;
			
			*(*buf) = (l>>8);
			(*buf)++;
			decrease--;
			
			*(*buf) = (l);
			(*buf)++;
			decrease--;
		}

		else if(ret-l == 5){
			*(*buf) = 0x83;
			(*buf)++;
			decrease--;

			*(*buf) = (l>>16);
			(*buf)++;
			decrease--;

			*(*buf) = (l>>8);
			(*buf)++;
			decrease--;

			*(*buf) = (l);
			(*buf)++;
			decrease--;
		}
		else if(ret-l == 6){
			*(*buf) = 0x84;
			(*buf)++;
			decrease--;

			*(*buf) = (l>>24);
			(*buf)++;
			decrease--;

			*(*buf) = (l>>16);
			(*buf)++;
			decrease--;

			*(*buf) = (l>>8);
			(*buf)++;
			decrease--;

			*(*buf) = (l);
			(*buf)++;
			decrease--;
		}

		l = signerCert_adjustLen( signCertdataLen,decrease );
		if(l<=0){
			return l;
		}

		*(*buf) = 0x04; 
		(*buf)++;
		decrease--;
		
		if(l- signCertdataLen == 2){
			*(*buf) = signCertdataLen;
			(*buf)++;
			decrease--;
		}
		else if(l-signCertdataLen == 3){
			*(*buf) = 0x81;
			(*buf)++;
			decrease--;
			*(*buf) = signCertdataLen;
			(*buf)++;
			decrease--;
		}
		else if(l-signCertdataLen == 4){
			*(*buf) = 0x82;
			(*buf)++;
			decrease--;
			
			*(*buf) = (signCertdataLen>>8);
			(*buf)++;
			decrease--;
			
			*(*buf) = (signCertdataLen);
			(*buf)++;
			decrease--;
		}
		else if(l-signCertdataLen == 5){
			*(*buf) = 0x83;
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen>>16);
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen>>8);
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen);
			(*buf)++;
			decrease--;
		}
		else if(l-signCertdataLen == 6){
			*(*buf) = 0x84;
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen>>24);
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen>>16);
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen>>8);
			(*buf)++;
			decrease--;

			*(*buf) = (signCertdataLen);
			(*buf)++;
			decrease--;
		}
		l = signCertdataLen;
		memcpy((*buf),signCertpData,l);
		(*buf)+=l;
		decrease-=l;

	}
	else
	{
		*(*buf) = 0xA0; 
		(*buf)++;
		decrease--;
		*(*buf) = 0x00; 
		(*buf)++;
		decrease--;

	}
	
	ret = buflen-decrease;
	
	if(ret!= signerCert_adjustLen( a, buflen))
	{
		return -_signer_encode_;
	}
	
	
	return ret;

}

/*
 
 SignedData ::= SEQUENCE
 {
 version            Version,
 digestAlgorithms   DigestAlgorithmIdentifiers,
 contentInfo        ContentInfo,
 certificates
    [0] IMPLICIT ExtendedCertificatesAndCertificates
 OPTIONAL,
    crls    [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 signerInfos SignerInfos
 }
 
 */


//编码
int signData_BerEncode(unsigned char ** buf, int buflen)
{
	int ret = 0;
	int a=0;int l = buflen; int a0,al,as,ac;
	int decrease = buflen;
	unsigned char* pp = (*buf);	
	decrease-=3;/*02 01 01(version)*/  
	
	ret = _EncodeSetDigests( &pp,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;

	ret = _EncodeData( &pp,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;

	ret = _EncodeSetCerts( &pp,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;

	ret = _EncodeSetSigner( &pp,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;

	as = buflen-decrease;
	ac = signerCert_adjustLen( as, buflen);
	if(ac<=0){
		return ac;
	}

	a0 = ac;/*30 xx*/
	al = signerCert_adjustLen( a0, buflen);
	if(al<=0){
		return al;
	}
	a = al;
	a+=strlen((char*)signedheader);
	ret = signerCert_adjustLen( a, buflen);
	if(ret<=0){
		return ret;
	}
	
//////////////////////////////////////////////////////////////////////////
    
    //SEQUENCE signData
	decrease = buflen;
	*(*buf) = 0x30; 
	(*buf)++;
	decrease--;
	
	if(ret- a == 2){
		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;

		*(*buf) = a;
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 5){
		*(*buf) = 0x83;
		(*buf)++;
		decrease--;

		*(*buf) = (a>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}
	else if(ret-a == 6){
		*(*buf) = 0x84;
		(*buf)++;
		decrease--;

		*(*buf) = (a>>24);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a);
		(*buf)++;
		decrease--;
	}

    //signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
	l = strlen((char*)signedheader);
	memcpy((*buf),signedheader,l);
	(*buf)+=l;
	decrease-=l;
    
    
	*(*buf) = 0xA0; 
	(*buf)++;
	decrease--;
	
	if(al- a0 == 2){
		*(*buf) = a0;
		(*buf)++;
		decrease--;
	}
	else if(al- a0 == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;
		*(*buf) = a0;
		(*buf)++;
		decrease--;
	}
	else if(al- a0 == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (a0>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (a0);
		(*buf)++;
		decrease--;
	}
	else if(al- a0 == 5){
		*(*buf) = 0x83;
		(*buf)++;
		decrease--;

		*(*buf) = (a0>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a0>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a0);
		(*buf)++;
		decrease--;
	}
	else if(al- a0 == 6){
		*(*buf) = 0x84;
		(*buf)++;
		decrease--;

		*(*buf) = (a0>>24);
		(*buf)++;
		decrease--;

		*(*buf) = (a0>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (a0>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (a0);
		(*buf)++;
		decrease--;
	}
    
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

	*(*buf) = 0x30; 
	(*buf)++;
	decrease--;
	
	if(ac- as == 2){
		*(*buf) = as;
		(*buf)++;
		decrease--;
	}
	else if(ac- as == 3){
		*(*buf) = 0x81;
		(*buf)++;
		decrease--;

		*(*buf) = as;
		(*buf)++;
		decrease--;
	}
	else if(ac- as == 4){
		*(*buf) = 0x82;
		(*buf)++;
		decrease--;
		
		*(*buf) = (as>>8);
		(*buf)++;
		decrease--;
		
		*(*buf) = (as);
		(*buf)++;
		decrease--;
	}
	else if(ac- as == 5){
		*(*buf) = 0x83;
		(*buf)++;
		decrease--;

		*(*buf) = (as>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (as>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (as);
		(*buf)++;
		decrease--;
	}
	else if(ac- as == 6){
		*(*buf) = 0x84;
		(*buf)++;
		decrease--;

		*(*buf) = (as>>24);
		(*buf)++;
		decrease--;

		*(*buf) = (as>>16);
		(*buf)++;
		decrease--;

		*(*buf) = (as>>8);
		(*buf)++;
		decrease--;

		*(*buf) = (as);
		(*buf)++;
		decrease--;
	}
    
/////////////////////////////////////////////////////////////////////////
    
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
    
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
    
    //DigestAlgorithmIdentifiers
	ret = _EncodeSetDigests( buf,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;
	
    //ContentInfo
	ret = _EncodeData( buf,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;
	
    //certificates
	ret = _EncodeSetCerts( buf,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;
	
    //signerInfos
	ret = _EncodeSetSigner( buf,decrease);
	if(ret<=0){
		return ret;
	}
	decrease-=ret;
	

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
	ret = buflen-decrease;
	
	if(ret!= signerCert_adjustLen( a, buflen))
	{
		return -_signer_encode_;
	}
	return ret;
}
//解码　

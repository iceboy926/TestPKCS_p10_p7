#include "sgncer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

unsigned char * pID = 0;
int  idLen = 0;
unsigned char * pCert = 0;
int  certLen = 0;

int getID(void);

//_signerCert::_signerCert()
//{
//	pCert = 0;
//	certLen = 0;
//	
//	pID = 0;
//	idLen = 0;
//
//}
//_signerCert::~_signerCert()
//{
//	if(pCert){
//		free(pCert);
//	}
//	if(pID){
//		free(pID);
//	}
//	pCert = 0;
//	certLen = 0;
//	
//	pID = 0;
//	idLen = 0;
//	
//}

//设置证书　而得到证书的标识
// #define _cert_memory_	0xc1
// #define _cert_encode_	0xc2
// #define _cert_io_		0xc3

	
int signerCert_SetCert(unsigned char * dCert,int  dLen)
{
	int ret = 0;
	if(dCert == NULL){
		return -_cert_io_;
	}
	if(pCert){
		free(pCert);
		pCert =0;certLen = 0;
	}
	pCert = (unsigned char*)malloc(dLen+1);
	if(pCert == NULL){
		return -_cert_memory_;
	}

	memcpy(pCert,dCert,dLen);
	certLen = dLen;
//释放ID 
	if(pID){
		free(pID);pID=0;idLen = 0;
	}
//解析证书　而得到　ID

//	ret = getID();
//	return ret;
    
    return certLen;
}

int signerCert_GetCert(unsigned char * dCert,int  dLen)
{
	int ret = 0;
	
	if(pCert == NULL){
		return -_cert_memory_;
	}
	if(dLen< certLen){
		return -_cert_io_;
	}

	if(dCert == NULL){
		return -_cert_io_;
	}

	memcpy(dCert, pCert,certLen);
	ret = certLen;
	return ret;
}

int signerCert_GetCertlen()
{
    return certLen;
}


int signerCert_Get_SerialNumber(unsigned char * dCert,int  dLen)
{
	int ret = 0;
	
	if(pID == NULL){
		return -_cert_memory_;
	}
	if(dLen< idLen){
		return -_cert_io_;
	}
	
	if(dCert == NULL){
		return -_cert_io_;
	}
	
	memcpy(dCert, pID,idLen);
	ret = idLen;
	return ret;
}

	
int getID(void)
{
	int ret = 0;
	if(pCert == NULL){
		return -_cert_encode_;
	}
	if(certLen <=0 ){
		return -_cert_encode_;
	}
//    unsigned char * ppCert = pCert;
//    X509 *certX509 = d2i_X509(NULL, (const unsigned char**)&ppCert, certLen);
//
//    //get issuer name
//    X509_NAME* pX509issuer = X509_get_issuer_name(certX509);
//    unsigned long int issuerLen = i2d_X509_NAME(pX509issuer,NULL);
//    unsigned char * pissuer = new unsigned char[issuerLen];
//    memset(pissuer, 0, issuerLen);
//    unsigned char * ppissuer = pissuer;
//    issuerLen = i2d_X509_NAME(pX509issuer,&ppissuer);
//
//    //get serial number
//    ASN1_INTEGER* pSNumber = X509_get_serialNumber(certX509);
//    unsigned long int SNumberLen = i2d_ASN1_INTEGER(pSNumber, NULL);
//    unsigned char * psn = new unsigned char[SNumberLen];
//    memset(psn, 0, SNumberLen);
//    unsigned char * ppsn = psn;
//    SNumberLen = i2d_ASN1_INTEGER(pSNumber,&ppsn);
//    
//    idLen = SNumberLen + issuerLen ;
//    pID = (unsigned char* )malloc(idLen);
//    if( pID == NULL)
//    {
//        return -_cert_memory_;
//    }
//    memcpy(pID, pissuer,issuerLen);
////    pID[issuerLen] = 0x02;
//    memcpy(&pID[issuerLen],psn,SNumberLen);
//    ret = idLen;
   	return ret;
}


//编码和解码
int signerCert_Encode_SerialNumber(unsigned char ** buf,int  bufLen)
{
	int ret = 0;
	if(pID == NULL){
		return -_cert_encode_;
	}
	if(idLen<=0){
		return -_cert_encode_;
	}
	ret = signerCert_adjustLen( idLen, bufLen);
	if( ret<=0){
		return ret;
	}

	*(*buf) = 0x30; 
	(*buf)++;
	
	if(ret-idLen == 2){
		*(*buf) = idLen;
		(*buf)++;
	}
	else if(ret-idLen == 3){
		*(*buf) = 0x81;
		(*buf)++;
		*(*buf) = idLen;
		(*buf)++;
	}
	else if(ret-idLen == 4){
		*(*buf) = 0x82;
		(*buf)++;

		*(*buf) = (idLen>>8);
		(*buf)++;

		*(*buf) = (idLen);
		(*buf)++;
	}
//拷贝的
	memcpy((*buf),pID,idLen  );
	(*buf)+=idLen;


	return ret;
}



int  signerCert_adjustLen( int contentLen, int inputLen)
{
	int ret = contentLen;
	
	int i;
	for(i=0;i<_max_encode_exponent;i++){
		ret>>=8;
		if(ret ==0)
        {
            break;
        }
	}

	if(i==0){
		if( contentLen<128)
			ret = contentLen + 2;
		else
			ret = contentLen + 3;
	}
	else if(i == 1){
		ret = contentLen + 4;
	}
	else if(i == 2){
		ret = contentLen + 5;
	}
	else if(i == 3){
		ret = contentLen + 6;
	}
	else if(i == 4){
		ret = contentLen + 7;
	}
	else if(i == 5){
		ret = contentLen + 8;
	}
	else if(i == 6){
		ret = contentLen + 9;
	}
	else if(i == 7){
		ret = contentLen + 10;
	}
	if(i==_max_encode_exponent){
		return -_cert_io_;
	}

	if(ret>inputLen){
		return -_cert_io_;
	}

	return ret;

}

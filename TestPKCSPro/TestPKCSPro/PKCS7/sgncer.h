#ifndef _SIGNER_CERTIFICATE_H__
#define _SIGNER_CERTIFICATE_H__

#define _cert_memory_	0xc1
#define _cert_encode_	0xc2
#define _cert_io_		0xc3


#define _max_encode_exponent  0x08



    //
int signerCert_adjustLen( int contentLen, int inputLen);
    //设置证书　而得到证书的标识
int signerCert_SetCert(unsigned char * dCert,int  dLen);

int signerCert_GetCert(unsigned char * dCert,int  dLen);
	//编码和解码
int signerCert_Encode_SerialNumber(unsigned char ** buf,int  bufLen);
	//得到ID
int signerCert_GetID(unsigned char * dCertID,int  dLen);

int signerCert_GetCertlen();


#endif


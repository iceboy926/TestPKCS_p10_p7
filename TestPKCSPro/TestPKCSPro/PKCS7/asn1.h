
#ifndef BOOL

#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ERROR_SUCCESS           0
#define DC_ERROR_FUNC_PARAM     1
#define DC_ERROR_MEMORY_ALLOC   2


#ifdef __cplusplus
extern "C" { 
#endif 

#include "platform_type_def.h"
    
//typedef unsigned long DWORD;
//typedef unsigned char BYTE, CHAR;
//    typedef int INT;

    
// ASN.1 routines
//
DWORD ber_encode_INTEGER(BOOL length_only,
                            BYTE ** ber_int,
                            DWORD * ber_int_len,
                            BYTE * data,
                            DWORD data_len);

DWORD   ber_encode_OCTET_STRING(BOOL length_only,
                                BYTE ** str,
                                DWORD * str_len,
                                BYTE * data,
                                DWORD data_len);
    
DWORD   ber_encode_PRINTABLE_STRING(BOOL length_only,
                                    BYTE ** str,
                                    DWORD * str_len,
                                    BYTE * data,
                                    DWORD data_len);
    
DWORD   ber_encode_BIT_STRING(BOOL length_only,
                                        BYTE ** str,
                                        DWORD * str_len,
                                        BYTE * data,
                                        DWORD data_len);
    
DWORD ber_encode_UTF8_STRING(BOOL length_only,
                                 BYTE ** str,
                                 DWORD * str_len,
                                 BYTE * data,
                                 DWORD data_len);
    
DWORD ber_encode_UTC_TIME(BOOL length_only,
                              BYTE ** str,
                              DWORD * str_len,
                              BYTE * data,
                              DWORD data_len);

    
DWORD ber_encode_IA5tring(BOOL length_only,
                              BYTE ** str,
                              DWORD * str_len,
                              BYTE * data,
                              DWORD data_len);
    
DWORD ber_encode_UNICODE_STRING(BOOL length_only,
                                    BYTE ** str,
                                    DWORD * str_len,
                                    BYTE * data,
                                    DWORD data_len);

DWORD ber_encode_OBJECT_IDENTIFIER(BOOL length_only,
								   BYTE ** identifier,
								   DWORD * identifier_len,
								   BYTE * data,
								   DWORD data_len);
    
DWORD   ber_encode_SEQUENCE(BOOL length_only,
                                BYTE ** seq,
                                DWORD * seq_len,
                                BYTE * data,
                                DWORD data_len);
    
DWORD   ber_encode_SET(BOOL length_only,
                                BYTE ** set,
                                DWORD * set_len,
                                BYTE * data,
                                DWORD data_len);
    
DWORD  ber_encode_Optional(BOOL length_only,
                             BYTE ** set,
                             DWORD * set_len,
                             BYTE * data,
                             DWORD data_len);
    
DWORD   ber_decode_INTEGER(BYTE * ber_int,
                               BYTE ** data,
                               DWORD * data_len,
                               DWORD * field_len);
    
DWORD   ber_decode_OCTET_STRING(BYTE * str,
                                    BYTE ** data,
                                    DWORD * data_len,
                                    DWORD * field_len);
    
DWORD ber_decode_OBJECT_IDENTIFIER(BYTE * identifier,
								   BYTE ** data,
								   DWORD * data_len,
								   DWORD * field_len);



DWORD   ber_decode_SEQUENCE(BYTE * seq,
                            BYTE ** data,
                            DWORD * data_len,
                            DWORD * field_len);

DWORD ber_decode_RSAPrivateKey(BYTE * data,
                               DWORD data_len,
                               BYTE ** n,
							   DWORD * pulN,
                               BYTE ** e,
							   DWORD * pulE,
                               BYTE ** d,
							   DWORD * pulD,
                               BYTE ** prime1,
							   DWORD * pulPrime1,
                               BYTE ** prime2,
							   DWORD * pulPrime2,
                               BYTE ** exponent1,
							   DWORD * pulExponent1,
                               BYTE ** exponent2,
							   DWORD * pulExponent2,
                               BYTE ** coeff,
							   DWORD * pulCoeff);


DWORD ber_encode_EVPPrivateKey_CFCA(BOOL length_only,
									BYTE ** data,
									DWORD * data_len,
									BYTE	* pbEncryptedSysmKey,
									DWORD ulEncryptedSysmKeyLen,
									BYTE	* pbEncryptedPrivateKey,
									DWORD ulEncryptedPrivateKeyLen);

DWORD ber_decode_EVPPrivateKey_CFCA(BYTE * data,
									DWORD data_len,
									BYTE	** pbAsymAlgId,
									DWORD * pulAsymAlgIdLen,
									BYTE	** pbSymAlgId,
									DWORD * pulSymAlgIdLen,
									BYTE	** pbEncryptedSysmKey,
									DWORD * pulEncryptedSysmKeyLen,
									BYTE	** pbEncryptedPrivateKey,
									DWORD * pulEncryptedPrivateKeyLen);

#ifdef __cplusplus 
} 
#endif 

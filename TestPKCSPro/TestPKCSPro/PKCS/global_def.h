//
//  global_def.h
// 
//
//
// 
//

#ifndef global_def_h
#define global_def_h


#define M_MD5             0x0F01
#define M_SHA1            0x0F02
#define M_SHA224          0x0F03
#define M_SHA256          0x0F04
#define M_SHA384          0x0F05
#define M_SHA512          0x0F06
#define M_SM2             0x0F07


#define AT_KEYEXCHANGE            1
#define AT_SIGNATURE              2

#define T_RSAKEY                  0x01
#define T_SM2KEY                  0x02


#define CKU_SO                    0
#define CKU_USER                  1


#define TOKEN_INFO_STORAGE        0
#define PKI_FILE_PUB_STORAGE      1
#define PKI_FILE_PRV_STORAGE      2
#define PKI_FILE_INDEX_STORAGE    3
#define PKI_FILE_INDEX_EX_STORAGE 4



////hash
#define S_HASH_INIT               0x0
#define S_HASH_UPDATE             0x01
#define S_HASH_FINAL              0x02
#define NO_DISPLAY_MODE           0x0


#define ALG_HASH_SM3              0x04
#define ALG_HASH_SHA256           0x01
#define ALG_HASH_SHA1             0x00

#define MAX_PATH                  260

#define MAX_DATA_PACKAGE_LEN      0xA0

#define APDU_LEN                  1024


//国密算法相关标识
#define SM2_MODULUS_BITS_LEN 256
#define SM2_MAX_XCOORDINATE_BITS_LEN 512
#define SM2_MAX_YCOORDINATE_BITS_LEN 512
#define SM2_MAX_MODULUS_BITS_LEN 512
#define SM2_MAX_MODULUS_LEN   ((SM2_MAX_MODULUS_BITS_LEN + 7) / 8)
#define CALG_SM2_SIGN (ALG_CLASS_SIGNATURE | ALG_TYPE_SM2 | ALG_SID_SM2_ANY)
#define CALG_SM2_KEYX (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_SM2 | ALG_SID_SM2_ANY)
#define ALG_TYPE_SM2 (15 << 9)
#define ALG_SID_SM2_ANY 0
#define CALG_SM3 (ALG_CLASS_HASH| ALG_TYPE_ANY | ALG_SID_SM3)
#define CALG_SM1 (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SM1)
#define CALG_SM4 (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SM4)
#define CALG_SSF33 (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_SSF33)
#define ALG_SID_SM3 15
#define ALG_SID_SM1	0x22
#define ALG_SID_SM4	0x23
#define ALG_SID_SSF33 0x21

// typedef struct _PUBLICKEYSTRUC {
// 	BYTE bType; //取值为：PRIVATEKEYBLOB (0x7)
// 	BYTE bVersion; //取值为：CUR_BLOB_VERSION (0x2)
// 	WORD reserved; //取值为：0x1—代表SM2私钥是加密的格式
// 	ALG_ID aiKeyAlg; //取值为：CALG_SM2_KEYX
// } BLOBHEADER, PUBLICKEYSTRUC;

/*
 *1、BLOBHEADER取值目前可忽略
 *2、SM2公钥的X、Y值为小字节序（LITTLE-ENDIAN），且均为32个byte，在Token层是大端存储，CSP层CFCA要求以小端导入导出
 *因此XCoordinate、YCoordinate的后32byte均补0。
 */
typedef struct _SM2PUBLICKEYBLOB{
    unsigned long BitLen; //模数的实际位长度，取值为：256
    unsigned char XCoordinate[SM2_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char YCoordinate[SM2_MAX_YCOORDINATE_BITS_LEN/8];
}SM2PUBLICKEYBLOB, *PSM2PUBLICKEYBLOB;

/*
 *	SM2私钥数据结构
 */
typedef struct _SM2PRIVATEKEYBLOB{
    unsigned long	BitLen;
    unsigned char	PrivateKey[SM2_MAX_MODULUS_BITS_LEN/8];
}SM2PRIVATEKEYBLOB, *PSM2PRIVATEKEYBLOB;


/*
 *	SM2密钥对数据结构
 */
typedef struct _SM2KEYPAIRBLOB{
    unsigned long BitLen;
    unsigned char XCoordinate[SM2_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char YCoordinate[SM2_MAX_YCOORDINATE_BITS_LEN/8];
    unsigned char PrivateKey[SM2_MAX_MODULUS_BITS_LEN/8];
}SM2KEYPAIRBLOB, *PSM2KEYPAIRBLOB;
/*
 *1、参数BitLen的值代表加密私钥的实际位长度。
 *2、加密私钥EncryptedPrivateKey格式为C1||C2||C3。C1（x, y），
 其中x,y分别为32字节曲线点分量，C2为加密的数据，C3为32字节SM3杂凑值。
 *3、解密后的SM2密钥对为x||y||d, 其中x，y是32字节的公钥坐标点，d是32字节的私钥。
 */
typedef struct _SM2PRIVATEKEYBLOB_CFCA {
    unsigned long AlgID; //取值为：CALG_SM2_SIGN 或 CALG_SM2_KEYX
    unsigned long EncryptedPrivateKeyBitLen; //加密SM2私钥EncryptedPrivateKey的实际位(bit)长度
    unsigned char *EncryptedPrivateKey; //加密的SM2密钥对（公私钥）数据
}SM2PRIVATEKEYBLOB_CFCA, *PSM2PRIVATEKEYBLOB_CFCA;

typedef struct Struct_SM2CIPHERBLOB
{
    unsigned char  XCoordinate[SM2_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char  YCoordinate[SM2_MAX_XCOORDINATE_BITS_LEN/8];
    unsigned char  Hash[32];
    unsigned long CipherLen;
    unsigned char  Cipher[1];
} SM2CIPHERBLOB, *PSM2CIPHERBLOB;

typedef struct Struct_ENVELOPEDKEYBLOB
{
    unsigned long Version;           // 当前版本为 1
    unsigned long ulSymmAlgID;      // 对称算法标识，限定ECB模式
    unsigned long ulBits;					// 加密密钥对的密钥位长度
    unsigned char  cbEncryptedPriKey[64]; // 加密密钥对私钥的密文, ENC(32字节0x00+32字节实际私钥)
    SM2PUBLICKEYBLOB PubKey; // 加密密钥对的公钥
    SM2CIPHERBLOB SM2CipherBlob;// 用保护公钥加密的对称密钥密文
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;





#endif /* global_def_h */

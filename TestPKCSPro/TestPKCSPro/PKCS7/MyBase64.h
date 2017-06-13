#ifndef __MY_BASE64_H__
#define __MY_BASE64_H__


#ifdef __cplusplus
extern "C" {
#endif

	//return >0: output string length, < 0: error code
	int myBase64Encode(unsigned char *pInData, unsigned int iInlen, char *pOutStr, unsigned int *pOutLen);
	int myBase64Decode(char *pInStr, char *pOutBuff, unsigned int *pOutLen);
    
#ifdef __cplusplus
}
#endif

#endif //__MY_BASE64_H__


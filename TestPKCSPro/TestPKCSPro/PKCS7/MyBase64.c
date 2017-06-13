#include "MyBase64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static const char Base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int _GetBase64Index(char ch);
int _IsBase64String(char *pStr);// return = 0 success, < 0,error code, > 0 first error charactor(begin  from 1);
bool _isbase64char(char c);


int myBase64Encode(unsigned char *pInData, unsigned int iInlen, char *pOutStr, unsigned int *pOutLen)
{
	//common check input paramters

	char *pbuff = NULL;
	unsigned int ibufflen = 0;
	int iModule = iInlen % 3;
	if(0 == iModule)
	{
		ibufflen = iInlen/3 * 4;	
	}
	else
	{
		ibufflen = (iInlen/3+1)*4;
	}

	//length check
	if( NULL == pOutStr || 0 == *pOutLen)
	{
		*pOutLen = ibufflen;//return real buffer length
		return ibufflen;
	}
	if(*pOutLen < ibufflen)
	{
		return -1; //buffer size too small
	}

	pbuff = (char *)malloc(ibufflen);
	memset(pbuff, 0x00, ibufflen);

	int idatalen = iInlen - iModule;
	unsigned char a1,a2,a3;
	int i, j;
	for(i = 0, j = 0; i < idatalen; i+=3, j+=4)
	{
		a1 = pInData[i] & 0xff;
		a2 = pInData[i+1] & 0xff;
		a3 = pInData[i+2] & 0xff;

		pbuff[j] = Base64Table[(a1 >>2) & 0x3f];
		pbuff[j+1] = Base64Table[((a1 & 0x03)<<4 | (a2 >>4)) & 0x3f];
		pbuff[j+2] = Base64Table[((a2 & 0x0f)<<2 | (a3 >> 6)) &0x3f];
		pbuff[j+3] = Base64Table[a3 & 0x3f];
	}

	
	switch(iModule) {
	case 0:
		//do nothing
		break;
	case 1:
		a1 = pInData[i] & 0xff;
		
		pbuff[j] = Base64Table[(a1 >>2) & 0x3f];
		pbuff[j+1] = Base64Table[((a1 & 0x03)<<4) & 0x3f];
		pbuff[j+2] = '=';//padding =
		pbuff[j+3] = '=';
		break;
	case 2:
		a1 = pInData[i] & 0xff;
		a2 = pInData[i+1] & 0xff;
		
		pbuff[j] = Base64Table[(a1 >>2) & 0x3f];
		pbuff[j+1] = Base64Table[((a1 & 0x03)<<4 | (a2 >>4)) & 0x3f];
		pbuff[j+2] = Base64Table[((a2 & 0x0f)<<2) &0x3f];
		pbuff[j+3] = '=';//padding =
		break;
	default:
		break;
	}

//	memcpy_s(pOutStr, ibufflen, pbuff, ibufflen);
    memcpy(pOutStr, pbuff, ibufflen);
	*pOutLen = ibufflen;

	if(pbuff != NULL)
	{
		free(pbuff);
		pbuff = NULL;
	}
	return ibufflen;
}
int myBase64Decode(char *pInStr, char *pOutBuff, unsigned int *pOutLen)
{
	//
	if(0 != _IsBase64String(pInStr))
		return -1;//not base64 string
	int iInLen = strlen(pInStr);
	int iOutLen = 0;
	int iPaddingNum = 0;
	if('=' == pInStr[iInLen -2])
	{
		iOutLen = iInLen/4 *3 -2;
		iPaddingNum = 2;
	}
	else if('=' == pInStr[iInLen -1])
	{
		iOutLen = iInLen/4*3-1;
		iPaddingNum = 1;
	}
	else
	{
		iOutLen = iInLen/4*3;
		iPaddingNum = 0;
	}

	if(NULL == pOutBuff || 0 == *pOutLen)
	{
		*pOutLen = iOutLen;
		return iOutLen;
	}
	if(iOutLen > *pOutLen)
	{
		return -1; //out buffer is too small
	}

	char *pBuff = NULL;
	//pBuff = new char[iOutLen+1];
    pBuff = malloc(iOutLen+1);
	memset(pBuff, 0x00, iOutLen+1);

	int i,j;
	unsigned char b1,b2,b3,b4;
	for(i =0, j= 0; i < iInLen-4; i+=4, j+=3)
	{
		b1 = _GetBase64Index(pInStr[i]);
		b2 = _GetBase64Index(pInStr[i+1]);
		b3 = _GetBase64Index(pInStr[i+2]);
		b4 = _GetBase64Index(pInStr[i+3]);

		pBuff[j] = ((b1 << 2) | (b2 >> 4)) & 0xff;
		pBuff[j + 1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
		pBuff[j + 2] = ((b3 << 6) | b4) & 0xff;
	}

	switch(iPaddingNum) {
	case 0:
		b1 = _GetBase64Index(pInStr[i]);
		b2 = _GetBase64Index(pInStr[i+1]);
		b3 = _GetBase64Index(pInStr[i+2]);
		b4 = _GetBase64Index(pInStr[i+3]);
		
		pBuff[j] = ((b1 << 2) | (b2 >> 4)) & 0xff;
		pBuff[j + 1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
		pBuff[j + 2] = ((b3 << 6) | b4) & 0xff;
		break;
	case 1:
		b1 = _GetBase64Index(pInStr[i]);
		b2 = _GetBase64Index(pInStr[i+1]);
		b3 = _GetBase64Index(pInStr[i+2]);
		b4 = _GetBase64Index(pInStr[i+3]);
		
		pBuff[j] = ((b1 << 2) | (b2 >> 4)) & 0xff;
		pBuff[j + 1] = ((b2 << 4) | (b3 >> 2)) & 0xff;

		break;
	case 2:
		b1 = _GetBase64Index(pInStr[i]);
		b2 = _GetBase64Index(pInStr[i+1]);
		b3 = _GetBase64Index(pInStr[i+2]);
		b4 = _GetBase64Index(pInStr[i+3]);
		
		pBuff[j] = ((b1 << 2) | (b2 >> 4)) & 0xff;
		break;
	default:
		break;
	}

	memcpy(pOutBuff, pBuff, iOutLen);
	*pOutLen =  iOutLen;
	if(pBuff != NULL)
	{
		free(pBuff);
		pBuff = NULL;
	}
	return iOutLen;
}
int _GetBase64Index(char ch)
{
	if(ch >= 'A'&&ch <= 'Z')
		return ch -'A';
	if(ch >= 'a'&&ch <= 'z')
		return ch -'a' + 26;
	if(ch >= '0'&&ch <= '9')
		return ch -'0' + 52;
	if(ch == '+')
		return 62;
	if(ch =='/')
		return 63;
	return 0;
}
int _IsBase64String(char *pStr)
{
	if(NULL == *pStr)
		return -1;
	int iLen = strlen(pStr);
	if(iLen % 4 != 0)
		return -2;
	for(int i = 0; i < iLen; i++)
	{
		if(!_isbase64char(pStr[i]))
		{
			if(pStr[i] =='=')
			{
				if(i == iLen-1)
				{
					return 0;
				}
				else if((i == iLen-2)&&(pStr[iLen-1] == '='))
				{
					return 0;
				}
				else
					return i+1;
			}
		}
	}
	return 0;
}
bool _isbase64char(char ch)
{
	if(ch >= 'A'&&ch <= 'Z')
		return true;
	if(ch >= 'a'&&ch <= 'z')
		return true;
	if(ch >= '0'&&ch <= '9')
		return true;
	if(ch == '+'||ch =='/')
		return true;
	return false;
}



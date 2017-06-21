/*

Auther Version Data Description
*/

#ifndef _HD_TYPE_DEF_H_
#define _HD_TYPE_DEF_H_


typedef char INT8;
typedef short INT16;
typedef int INT32;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long DWORD;

typedef INT32 INT;
typedef UINT8 BYTE;
typedef BYTE* PBYTE;
typedef UINT8 byte;
typedef char CHAR;
typedef UINT8 UCHAR;
typedef INT16 SHORT;
typedef UINT16 USHORT;
typedef long LONG;
typedef unsigned long ULONG;
typedef UINT32 UINT;
typedef UINT16 WORD;

typedef unsigned long* PDWORD;


#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG *)-1)

#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))

#ifndef LOWORD
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#endif

#ifndef HIWORD
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#endif

#ifndef LOBYTE
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#endif

#ifndef HIBYTE
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))
#endif

#define min(_a,_b) ((_a)>(_b)?(_b):(_a))
#define max(_a,_b) ((_a)>(_b)?(_a):(_b))



#endif  //_HD_TYPE_DEF_H_

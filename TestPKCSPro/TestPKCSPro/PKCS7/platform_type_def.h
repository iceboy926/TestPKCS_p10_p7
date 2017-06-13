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
typedef unsigned long DWORD;
typedef unsigned long* PDWORD;
typedef UINT32 FLAGS;
typedef void* HANDLE;
typedef UINT32 DWORD_PTR;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef LPSTR LPTSTR;
typedef LPCSTR LPCTSTR;
typedef char TCHAR;
typedef long HINSTANCE;

typedef long long int INT64;
typedef unsigned long long int UINT64;

typedef ULONG          CK_RV;
typedef ULONG          CK_USER_TYPE;

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
/* CK_LONG is new for v2.0 */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;
typedef unsigned char *   CK_BYTE_PTR;
typedef unsigned long *     CK_ULONG_PTR;

typedef unsigned short DEV_RES;


//hdzb type define
typedef INT8 hz_char;
typedef UINT8 hz_byte;
typedef INT8 hz_int8;
typedef UINT8 hz_uint8;
typedef INT16 hz_int16;
typedef UINT16 hz_uint16;
typedef INT32 hz_int32;
typedef UINT32 hz_uint32;
typedef INT64 hz_int64;
typedef UINT64 hz_uint64;
typedef UINT32 hz_bool;
typedef HANDLE hz_handle;
typedef void hz_void;
#define hz_true     TRUE
#define hz_false    FALSE
#define hz_null     NULL

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

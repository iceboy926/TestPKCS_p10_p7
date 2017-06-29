//
//  ViewController.m
//  TestPKCSPro
//
//  Created by zuoyongyong on 2017/6/5.
//  Copyright © 2017年 zuoyongyong. All rights reserved.
//

#import "ViewController.h"
#import "gzdercode.h"

@interface ViewController ()

@end

@implementation ViewController

static unsigned char replaced_userPubKey[65] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00
};

static unsigned char cert_pub[64] = {
    0x44, 0x46, 0xd0, 0x41, 0x32, 0x80, 0xb5, 0x95,
    0x82, 0xab, 0xea, 0xab, 0x87, 0xf5, 0x6b, 0xa4,
    0xbd, 0x87, 0xdc, 0xc7, 0xa4, 0x7a, 0xf0, 0xaf,
    0x49, 0x76, 0x07, 0xc6, 0xbf, 0x1a, 0x5d, 0x4d,
    0x44, 0x46, 0xd0, 0x41, 0x32, 0x80, 0xb5, 0x95,
    0x82, 0xab, 0xea, 0xab, 0x87, 0xf5, 0x6b, 0xa4,
    0xbd, 0x87, 0xdc, 0xc7, 0xa4, 0x7a, 0xf0, 0xaf,
    0x49, 0x76, 0x07, 0xc6, 0xbf, 0x1a, 0x5d, 0x4d
};

static unsigned char cert_sign[64] = {
    0x44, 0x46, 0xd0, 0x41, 0x32, 0x80, 0xb5, 0x95,
    0x82, 0xab, 0xea, 0xab, 0x87, 0xf5, 0x6b, 0xa4,
    0xbd, 0x87, 0xdc, 0xc7, 0xa4, 0x7a, 0xf0, 0xaf,
    0x49, 0x76, 0x07, 0xc6, 0xbf, 0x1a, 0x5d, 0x4d,
    0x44, 0x46, 0xd0, 0x41, 0x32, 0x80, 0xb5, 0x95,
    0x82, 0xab, 0xea, 0xab, 0x87, 0xf5, 0x6b, 0xa4,
    0xbd, 0x87, 0xdc, 0xc7, 0xa4, 0x7a, 0xf0, 0xaf,
    0x49, 0x76, 0x07, 0xc6, 0xbf, 0x1a, 0x5d, 0x4d
};



void str_replace(char * cp, int n, char * str, int len)
{
    int lenofstr = len;
    int i;
    char * tmp;
    //str3比str2短，往前移动
    if(lenofstr < n)
    {
        tmp = cp+n;
        while(*tmp)
        {
            *(tmp-(n-lenofstr)) = *tmp; //n-lenofstr是移动的距离
            tmp++;
        }
        *(tmp-(n-lenofstr)) = *tmp; //move '\0'
    }
    else
        //str3比str2长，往后移动
        if(lenofstr > n)
        {
            tmp = cp;
            while(*tmp) tmp++;
            while(tmp>=cp+n)
            {
                *(tmp+(lenofstr-n)) = *tmp;
                tmp--;
            }
        }
    memcpy(cp,str,lenofstr);
}

char *mystrstr(char *s1, int s1len,char *s2, int s2len)
{
    int n;
    int i = 0;
    if (*s2)                      //两种情况考虑
    {
        while(i < s1len)
        {
            for (n=0;*(s1+n)==*(s2+n);n++)
            {
                if (!*(s2+n+1))            //查找的下一个字符是否为'\0'
                {
                    return (char*)s1;
                }  
            }  
            s1++;
            i++;
        }  
        return NULL;  
    }  
    else  
    {  
        return (char*)s1;  
    }  
}

- (void)testencode
{
    
    DWORD dwRet = 0;
    
    //DWORD dwRet = berEncodeSubjectName(berSubjectName, &dwberSubjectNameLen, cndata, cndata_len, odata, odata_len, oudata, oudata_len, cdata, cdata_len, emaildata, emaildata_len);
    
    if(dwRet == ERROR_SUCCESS)
    {
        NSLog(@"encodeSubjectName SUCCESS");
    }
    else
    {
        NSLog(@"encodeSubjectName Failed");
    }

}

- (void)generatep10
{
    BYTE berCertReq[1024] = {0};
    DWORD dwberCertReq = sizeof(berCertReq);
    
    DWORD dwRet = PackPKCS10(cert_pub, sizeof(cert_pub), cert_sign, sizeof(cert_sign), berCertReq, &dwberCertReq);
    if(dwRet == 0)
    {
        NSLog(@"success");
    }
    else
    {
        NSLog(@"error");
    }
    
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
   NSString *strIn = @"1.2.156.10197.1.501";  //sm2-sm3sign
    
   NSString *strIn1 = @"2.5.29.15";
    
   // [self getTestOut:strIn1];
    
    [self generatep10];
 
}

void convertData(int intData, int N, char *szoutdata, int *poutdatalen)
{
    int temp = intData;
    char szout[128] = {0};
    int count = 0;
    int remainder = 0;
    int j = 0;

    
    while(temp)
    {
        remainder = temp % N;
        szout[j++] = remainder;
        temp = temp/N;
    }
    
    *poutdatalen = j;
    
    for(int i = 0; i < j; i++)
    {
        if(i == j-1)
        {
            szoutdata[i] = szout[j-i-1];
        }
        else
        {
            szoutdata[i] = szout[j-i-1]|0x80;
        }
    }
}

- (void)getTestOut:(NSString *)strin
{
    NSString *strOut = [NSString string];
    NSMutableArray *strArray = [NSMutableArray array];
    char szOutData[128] = {0};
    int outdataLen = 0;
    
    NSArray *arrayOut = [strin componentsSeparatedByString:@"."];
    
    NSString *strV1 = [arrayOut objectAtIndex:0];
    NSString *strV2 = [arrayOut objectAtIndex:1];
    
    szOutData[0] = 40*[strV1 intValue] + [strV2 intValue];
    
    [strArray addObject:[NSString stringWithFormat:@"0x%x", szOutData[0]]];

    
    for (int i = 2; i < [arrayOut count]; i++) {
        
        int value = [[arrayOut objectAtIndex:i] intValue];
        
        char szOutData[128] = {0};
        int len = 0;
        
        convertData(value, 128, szOutData, &len);
        
        for (int j = 0; j < len; j++) {
            
            int intValue = szOutData[j];
            [strArray addObject:[NSString stringWithFormat:@"0x%x", intValue]];
        }
    }
    
    
    NSLog(@"strArray is %@", strArray);
    
    
    return ;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end

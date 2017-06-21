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

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    char newdata[64] = {0x00};
    
    memset(newdata, 1, 64);
    
    unsigned char newPubkey[80] = {
        0x98, 0x65, 0x98, 0x65, 0x00, 0x76, 0x04, 0x20,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x98, 0x65, 0x98, 0x65, 0x98, 0x65, 0x98, 0x65
    };
    

    
    char *tempstr = mystrstr(newPubkey, sizeof(newPubkey), replaced_userPubKey, 64);
    if(tempstr == NULL)
    {
        NSLog(@"dsfsdfsd");
    }
    
    memcpy(tempstr, newdata, 64);
    
    
    BYTE berSubjectName[1024] = {0};
    DWORD dwberSubjectNameLen = sizeof(berSubjectName);
    
    BYTE cndata[] = "cn";
    DWORD cndata_len = strlen(cndata);
    
    BYTE odata[] = "testorg";
    DWORD odata_len = strlen(odata);
    
    BYTE oudata[] = "testorgunit";
    DWORD oudata_len = strlen(oudata);
    
    BYTE cdata[] = "zuoyy";
    DWORD cdata_len = strlen(cdata);
    
    BYTE emaildata[] = "zuoyy@gmrz-bj.com";
    DWORD emaildata_len = strlen(emaildata);
    
    
    
    DWORD dwRet = berEncodeSubjectName(berSubjectName, &dwberSubjectNameLen, cndata, cndata_len, odata, odata_len, oudata, oudata_len, cdata, cdata_len, emaildata, emaildata_len);
    
    if(dwRet == ERROR_SUCCESS)
    {
        NSLog(@"encodeSubjectName SUCCESS");
    }
    else
    {
        NSLog(@"encodeSubjectName Failed");
    }
    
    
//    BYTE testdata[5] = {0x45, 0x34, 0x12, 0x13, 0x14};
//    BYTE outdata[12] = {0};
//    DWORD dwoutlen = 12;
//    
//    asciiToHex(testdata, 5, outdata, &dwoutlen);
}



- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end

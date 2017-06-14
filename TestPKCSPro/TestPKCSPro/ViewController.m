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

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
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
    
    
    
    DWORD dwRet = encodeSubjectName(berSubjectName, &dwberSubjectNameLen, cndata, cndata_len, odata, odata_len, oudata, oudata_len, cdata, cdata_len, emaildata, emaildata_len);
    
    if(dwRet == ERROR_SUCCESS)
    {
        NSLog(@"encodeSubjectName SUCCESS");
    }
    else
    {
        NSLog(@"encodeSubjectName Failed");
    }
    
    
    BYTE testdata[5] = {0x45, 0x34, 0x12, 0x13, 0x14};
    BYTE outdata[12] = {0};
    DWORD dwoutlen = 12;
    
    asciiToHex(testdata, 5, outdata, &dwoutlen);
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end

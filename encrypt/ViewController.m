//
//  ViewController.m
//  encrypt
//
//  Created by Orangels on 16/9/8.
//  Copyright © 2016年 ls. All rights reserved.
//

#import "ViewController.h"
#import "AESCrypt.h"
#import "EncryptionTools.h"
@interface ViewController ()

@end

@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    NSString* userName = @"ls";
    NSString* password = @"123";
    NSString* encryptedData = [AESCrypt encrypt:userName password:password];
    NSLog(@"%@",encryptedData);
    
    NSLog(@"%@",[AESCrypt decrypt:encryptedData password:password]);
    
    NSString* str1 = [[EncryptionTools sharedEncryptionTools] encryptString:userName keyString:password iv:nil];
    NSLog(@"%@",str1);
    NSLog(@"%@",[[EncryptionTools sharedEncryptionTools] decryptString:str1 keyString:password iv:nil]);
    NSString* str2 = [EncryptionTools encrypt:userName encryptOrDecrypt:0 key:password];
    NSLog(@"%@",[EncryptionTools encrypt:str2 encryptOrDecrypt:1 key:password]);
}




- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end

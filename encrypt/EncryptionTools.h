//
//  EncryptionTools.h
//  encrypt
//
//  Created by Orangels on 16/9/8.
//  Copyright © 2016年 ls. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <CommonCrypto/CommonCrypto.h>
@interface EncryptionTools : NSObject
@property (nonatomic, assign) uint32_t algorithm;


+ (instancetype)sharedEncryptionTools;

+ (NSString *)encrypt:(NSString *)sText encryptOrDecrypt:(CCOperation)encryptOperation key:(NSString *)key;

- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;

- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv;


@end

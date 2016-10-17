//
//  EncryptionTools.m
//  encrypt
//
//  Created by Orangels on 16/9/8.
//  Copyright © 2016年 ls. All rights reserved.
//

#import "EncryptionTools.h"

@interface EncryptionTools ()
@property (nonatomic, assign) int keySize;
@property (nonatomic, assign) int blockSize;
@end


@implementation EncryptionTools

+ (instancetype)sharedEncryptionTools
{
    static EncryptionTools *instance;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
        instance.algorithm = kCCAlgorithmAES;
    });
    
    return instance;
}

- (void)setAlgorithm:(uint32_t)algorithm
{
    _algorithm = algorithm;
    switch (algorithm) {
        case kCCAlgorithmAES:
            self.keySize = kCCKeySizeAES128;
            self.blockSize = kCCBlockSizeAES128;
            break;
        case kCCAlgorithmDES:
            self.keySize = kCCKeySizeDES;
            self.blockSize = kCCBlockSizeDES;
            break;
        default:
            break;
    }
}

- (NSString *)encryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv
{
    
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    //定义一个长度为 self.keySize 的 C 字符串
    uint8_t cKey[self.keySize];
//    NSLog(@"之前 = %c",cKey[1]);
//    ckey 全部清空
    bzero(cKey, sizeof(cKey));
//    NSLog(@"之后 = %c",cKey[1]);
    
//    将 key 转换成 C 字符串
    [keyData getBytes:cKey length:self.keySize];
    //这里也可以直接将 NSString 的 key 转换成 C 字符串的 key,, 但是解密的时候也要相对应(要么都是直接转换,要么都是 uint8_t[self.keySize])
   const char * cKeyStr = [keyString UTF8String];
    
    
    // 设置iv,同 ckey,加密解密都可以用 cIvStr
    const void * cIvStr = [iv bytes];
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    int option = 0;
    /**
     kCCOptionPKCS7Padding                      CBC 的加密
     kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
     */
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        //位运算 等于 1
        option = kCCOptionPKCS7Padding;
    } else {
        //位运算 等于3
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [data length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    size_t encryptedSize = 0;
    
    /*
     CCCrypt 对称加密算法的核心函数(加密/解密)
     第一个参数：kCCEncrypt 加密/ kCCDecrypt 解密
     第二个参数：加密算法，默认使用的是 AES/DES
     第三个参数：加密选项 ECB/CBC
     kCCOptionPKCS7Padding                      CBC 的加密
     kCCOptionPKCS7Padding | kCCOptionECBMode   ECB 的加密
     第四个参数：加密密钥
     第五个参数：密钥的长度
     第六个参数：初始向量
     第七个参数：加密的数据
     第八个参数：加密的数据长度
     第九个参数：密文的内存地址
     第十个参数：密文缓冲区的大小
     第十一个参数：加密结果的大小
     */
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
        NSLog(@"成功加密");
    } else {
        free(buffer);
        NSLog(@"[错误] 加密失败|状态编码: %d", cryptStatus);
    }
    return [result base64EncodedStringWithOptions:0];
}


- (NSString *)decryptString:(NSString *)string keyString:(NSString *)keyString iv:(NSData *)iv{
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[self.keySize];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:self.keySize];
    
  const char * cKeyStr = [keyString UTF8String];
    
    // 设置iv
    uint8_t cIv[self.blockSize];
    bzero(cIv, self.blockSize);
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:self.blockSize];
        //位运算 等于 1
        option = kCCOptionPKCS7Padding;
    } else {
        //位运算 等于 3
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
//    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
    size_t bufferSize = [data length] + self.blockSize;
    void *buffer = malloc(bufferSize);
    
    // 开始解密
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          self.algorithm,
                                          option,
                                          cKey,
                                          self.keySize,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
        NSLog(@"成功解密");
    } else {
        free(buffer);
        NSLog(@"[错误] 解密失败|状态编码: %d", cryptStatus);
    }
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

//DES加密

+ (NSString *)encrypt:(NSString *)sText encryptOrDecrypt:(CCOperation)encryptOperation key:(NSString *)key
{
    const void *dataIn;
    size_t dataInLength;
    if (encryptOperation == kCCDecrypt)//传递过来的是decrypt 解码
    {
        //解码 base64
        NSData *decryptData = [[NSData alloc] initWithBase64EncodedString:sText options:0];//转成utf-8并decode
        dataInLength = [decryptData length];
        dataIn = [decryptData bytes];
    }
    else //encrypt
    {
        NSData* encryptData = [sText dataUsingEncoding:NSUTF8StringEncoding];
        dataInLength = [encryptData length];
        dataIn = (const void *)[encryptData bytes];
    }
    /*
     DES加密 ：用CCCrypt函数加密一下，然后用base64编码下，传过去
     DES解密 ：把收到的数据根据base64，decode一下，然后再用CCCrypt函数解密，得到原本的数据
     */
    CCCryptorStatus ccStatus;
    uint8_t *dataOut = NULL; //可以理解位type/typedef 的缩写（有效的维护了代码，比如：一个人用int，一个人用long。最好用typedef来定义）
    size_t dataOutAvailable = 0; //size_t 是操作符sizeof返回的结果类型
    size_t dataOutMoved = 0;
    dataOutAvailable = (dataInLength + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    dataOut = malloc( dataOutAvailable * sizeof(uint8_t));
    memset((void *)dataOut, 0x0, dataOutAvailable);//将已开辟内存空间buffer的首 1 个字节的值设为值 0
    NSString *initIv = @"12345678";
    const void *vkey = (const void *) [key UTF8String];
    const void *iv = (const void *) [initIv UTF8String];
    //CCCrypt函数 加密/解密
    ccStatus = CCCrypt(encryptOperation,// 加密/解密
                       kCCAlgorithmDES,// 加密根据哪个标准（des，3des，aes。。。。）
                       kCCOptionPKCS7Padding,// 选项分组密码算法(des:对每块分组加一次密 3DES：对每块分组加三个不同的密)
                       vkey, //密钥 加密和解密的密钥必须一致
                       kCCKeySizeDES,// DES 密钥的大小（kCCKeySizeDES=8）
                       iv, // 可选的初始矢量
                       dataIn, // 数据的存储单元
                       dataInLength,// 数据的大小
                       (void *)dataOut,// 用于返回数据
                       dataOutAvailable,
                       &dataOutMoved);
    NSString *result = nil;
    if (encryptOperation == kCCDecrypt)//encryptOperation==1 解码
    {
        //得到解密出来的data数据，改变为utf-8的字符串
        result = [[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)dataOut length:(NSUInteger)dataOutMoved] encoding:NSUTF8StringEncoding];
    }
    else //encryptOperation==0 （加密过程中，把加好密的数据转成base64的）
    {
        //编码 base64
        NSData *data = [NSData dataWithBytes:(const void *)dataOut length:(NSUInteger)dataOutMoved];
        result = [data base64EncodedStringWithOptions:0];
    }
    return result;
}

@end

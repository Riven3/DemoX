//
//  AESHelper.m
//  AES
//
//  Created by 刘彦直 on 2018/6/3.
//  Copyright © 2017年 com.zxevpop. All rights reserved.
//

#import "AESHelper.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "GTMBase64.h"

@interface AESHelper () {
    NSData *secretData;
    NSString *iv;
}

@end

@implementation AESHelper


//49,50,51,52,53,54,55,56,57,48,54,53,52,51,50,49
- (instancetype)initWithSecret:(NSString*)secret keyVector:(NSString *)vector {
    self = [super init];
    if (self) {
        iv = vector;
        //"1234567890654321"
        Byte saltBuff[] = {0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
        NSUInteger kAlgorithmKeySize = kCCKeySizeAES256;
        
        uint kPBKDFRounds = 1000;
        
        NSMutableData *derivedKey = [NSMutableData dataWithLength:kAlgorithmKeySize];
        NSData *salt = [NSData dataWithBytes:saltBuff length:kCCKeySizeAES128];
        CCKeyDerivationPBKDF(kCCPBKDF2,        // algorithm算法
                             secret.UTF8String,  // password密码
                             secret.length,      // passwordLength密码的长度
                             salt.bytes,           // salt内容
                             salt.length,          // saltLen长度
                             kCCPRFHmacAlgSHA1,    // PRF
                             kPBKDFRounds,         // rounds循环次数
                             derivedKey.mutableBytes, // derivedKey
                             derivedKey.length);   // derivedKeyLen derive:出自
        secretData = derivedKey;
    }
    return self;
}



- (NSString*)AESEncrypt:(NSString*)plainText {
    //源字符串->Base64字符串->Base64字符串作为UTF8字符串转NSData(洗码)
    NSData *tempData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *resultStr = [tempData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength|NSDataBase64Encoding76CharacterLineLength|NSDataBase64EncodingEndLineWithCarriageReturn|NSDataBase64EncodingEndLineWithLineFeed];
    NSData *plainData = [resultStr dataUsingEncoding:NSUTF8StringEncoding];

    if (plainData.length==0) {
        return nil;
    }
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    NSUInteger dataLength = plainData.length;
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    bzero(buffer, sizeof(buffer));
    
    size_t numBytesEncrypted = 0;

    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          secretData.bytes,
                                          kCCKeySizeAES256,
                                          iv.UTF8String,
                                          plainData.bytes,
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *encryptData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
        NSString *resultStr = [GTMBase64 encodeBase64Data:encryptData];//[encryptData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength|NSDataBase64Encoding76CharacterLineLength|NSDataBase64EncodingEndLineWithCarriageReturn|NSDataBase64EncodingEndLineWithLineFeed];
        return resultStr;
    }
    
    free(buffer);
    
    return nil;
}


- (NSString*)AESDecrypt:(NSString*)plainText {
    if (plainText.length==0) {
        return nil;
    }
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:plainText options:NSDataBase64DecodingIgnoreUnknownCharacters];

    NSUInteger dataLength = [cipherData length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          secretData.bytes,
                                          kCCKeySizeAES256,
                                          iv.UTF8String,
                                          cipherData.bytes,
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        //逆向加密时的洗码过程
        //NSData转为UTF8字符串->UTF8字符串转为Base64的NSData->Base64的NSData解码为普通字符串
        NSData *encryptData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
        NSString *base64String = [[NSString alloc] initWithData:encryptData encoding:NSUTF8StringEncoding];
        NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
        NSString *resultStr = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
        
        return resultStr;
    }
    
    free(buffer);
    return nil;
}



@end

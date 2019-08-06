//
//  AESHelper.h
//  AES
//
//  Created by 刘彦直 on 2018/6/3.
//  Copyright © 2017年 com.zxevpop. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AESHelper : NSObject

- (instancetype)initWithSecret:(NSString*)secret keyVector:(NSString *)vector;

- (NSString*)AESEncrypt:(NSString*)plainText;

- (NSString*)AESDecrypt:(NSString*)plainText;


@end

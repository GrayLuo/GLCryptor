//
//  HICryptor.h
//  QRCodeDemo
//
//  Created by Grey.Luo on 16/1/20.
//  Copyright © 2016年 Grey.Luo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#define kChosenCipherBlockSize	kCCBlockSizeAES128
#define kChosenCipherKeySize	kCCKeySizeAES128
#define kChosenDigestLength		CC_SHA1_DIGEST_LENGTH

@interface GLCryptor : NSObject
//key must be 16 bits length
+ (NSString *)encryptString:(NSString *)plainSourceStringToEncrypt key:(NSString *)key iv:(NSString *)iv;
+ (NSString *)decryptString:(NSString *)base64StringToDecrypt key:(NSString *)key iv:(NSString *)iv;
+ (NSData *)encrypt:(NSData *)plainText key:(NSString *)key iv:(NSString *)iv;
+ (NSData *)decrypt:(NSData *)plainText key:(NSString *)key iv:(NSString *)iv;
@end

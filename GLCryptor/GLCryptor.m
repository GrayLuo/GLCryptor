//
//  HICryptor.m
//  QRCodeDemo
//
//  Created by Grey.Luo on 16/1/20.
//  Copyright © 2016年 Grey.Luo. All rights reserved.
//

#import "GLCryptor.h"

@implementation GLCryptor

CCOptions _padding = kCCOptionPKCS7Padding;
+ (NSString *)encryptString:(NSString *)plainSourceStringToEncrypt key:(NSString *)key iv:(NSString *)iv{
    NSData *_secretData = [plainSourceStringToEncrypt dataUsingEncoding:NSASCIIStringEncoding];
    // !!!16 bits,You can use md5 to make sure key is 16 bits long
    NSData *encryptedData = [self encrypt:_secretData key:key iv:iv];
    return [encryptedData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

+ (NSString *)decryptString:(NSString *)base64StringToDecrypt key:(NSString *)key iv:(NSString *)iv{
    NSData *base64DataToDecrypt = [[NSData alloc]initWithBase64EncodedString:base64StringToDecrypt options:0];
    NSData *data = [self decrypt:base64DataToDecrypt key:key iv:iv];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSData *)encrypt:(NSData *)plainText key:(NSString *)key iv:(NSString *)iv{
    return [self doCipher:plainText context:kCCEncrypt key:key iv:iv];
}

+ (NSData *)decrypt:(NSData *)plainText key:(NSString *)key iv:(NSString *)iv{
    return [self doCipher:plainText context:kCCDecrypt key:key iv:iv];
}

+ (NSData *)doCipher:(NSData *)plainText context:(CCOperation)encryptOrDecrypt  key:(NSString *)key iv:(NSString *)iv{
    CCCryptorStatus ccStatus = kCCSuccess;
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    // A friendly helper pointer.
    uint8_t * ptr;
    CCOptions *pkcs7;
    pkcs7 = &_padding;

    // NSData *aSymmetricKey = [kEncryptKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aSymmetricKey = [key dataUsingEncoding:NSUTF8StringEncoding];

    // Initialization vector; dummy in this case 0's.
    //uint8_t iv[kChosenCipherBlockSize];
    //memset((void *) iv, 0x0, (size_t) sizeof(iv));
    const void *initIv = (const void *)[iv UTF8String];
    plainTextBufferSize = [plainText length];

    // We don't want to toss padding on if we don't need to
    if(encryptOrDecrypt == kCCEncrypt) {
        if(*pkcs7 != kCCOptionECBMode) {
            if((plainTextBufferSize % kChosenCipherBlockSize) == 0) {
                *pkcs7 = 0x0000;
            } else {
                *pkcs7 = kCCOptionPKCS7Padding;
            }
        }
    } else if(encryptOrDecrypt != kCCDecrypt) {
        //        NSLog(@"Invalid CCOperation parameter [%d] for cipher context.", *pkcs7 );
    }
    // *pkcs7 = kCCOptionECBMode;
    // Create and Initialize the crypto reference.
    //NSLog(@"pkcs7:%d",*pkcs7);
    ccStatus = CCCryptorCreate(encryptOrDecrypt,
                               kCCAlgorithmAES128,
                               *pkcs7,
                               (const void *)[aSymmetricKey bytes],
                               kChosenCipherKeySize,
                               initIv,
                               &thisEncipher
                               );

    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);

    // Allocate buffer.
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );

    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);

    // Initialize some necessary book keeping.
    ptr = bufferPtr;

    // Set up initial size.
    remainingBytes = bufferPtrSize;

    // Actually perform the encryption or decryption.
    ccStatus = CCCryptorUpdate(thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );

    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;

    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );

    totalBytesWritten += movedBytes;

    if(thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }

    if (ccStatus == kCCSuccess){

        cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    }
    else
        cipherOrPlainText = nil;

    if(bufferPtr) free(bufferPtr);
    
    return cipherOrPlainText;
}

@end

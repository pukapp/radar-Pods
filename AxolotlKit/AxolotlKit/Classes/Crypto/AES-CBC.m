//
//  Copyright (c) 2018 Open Whisper Systems. All rights reserved.
//

#import "AES-CBC.h"
#import "AxolotlExceptions.h"
#import "MessageKeys.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@implementation AES_CBC

#pragma mark AESCBC Mode

+ (NSData *)throws_encryptCBCMode:(NSData *)data withKey:(NSData *)key withIV:(NSData *)iv
{
    if (!data) {
        @throw [NSException exceptionWithName:CipherException reason:@"Missing data to encrypt." userInfo:nil];
    }
    if (data.length >= SIZE_MAX - kCCBlockSizeAES128) {
        @throw [NSException exceptionWithName:CipherException reason:@"Oversize data." userInfo:nil];
    }
    if (key.length != 32) {
        @throw [NSException exceptionWithName:CipherException reason:@"AES key should be 256 bits." userInfo:nil];
    }
    if (iv.length != 16) {
        @throw [NSException exceptionWithName:CipherException reason:@"AES-CBC IV should be 128 bits." userInfo:nil];
    }

    size_t bufferSize;
    ows_add_overflow(data.length, kCCBlockSizeAES128, &bufferSize);
    NSMutableData *_Nullable bufferData = [NSMutableData dataWithLength:bufferSize];
    OWSAssert(bufferData != nil);

    size_t bytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
        kCCAlgorithmAES128,
        kCCOptionPKCS7Padding,
        [key bytes],
        [key length],
        [iv bytes],
        [data bytes],
        [data length],
        bufferData.mutableBytes,
        bufferSize,
        &bytesEncrypted);

    if (cryptStatus == kCCSuccess) {
        return [bufferData subdataWithRange:NSMakeRange(0, bytesEncrypted)];
    } else {
        @throw [NSException exceptionWithName:CipherException
                                       reason:@"We encountered an issue while encrypting."
                                     userInfo:nil];
    }
}

+ (NSData *)throws_decryptCBCMode:(NSData *)data withKey:(NSData *)key withIV:(NSData *)iv
{
//    NSLog(@"throws_decryptCBCMode before: %ld", data.length);
    OWSLogDebug(@"throws_decryptCBCMode before: %ld", data.length);
    OWSLogDebug(@"throws_decryptCBCMode before: key: %@", key.description);
    OWSLogDebug(@"throws_decryptCBCMode before: iv: %@", iv.description);
    NSLog(@"throws_decryptCBCMode before: %ld", data.length);
    NSLog(@"throws_decryptCBCMode before: key: %@", key.description);
    NSLog(@"throws_decryptCBCMode before: iv: %@", iv.description);
    if (!data) {
        @throw [NSException exceptionWithName:CipherException reason:@"Missing data to decrypt." userInfo:nil];
    }
    if (data.length >= SIZE_MAX - kCCBlockSizeAES128) {
        @throw [NSException exceptionWithName:CipherException reason:@"Oversize data." userInfo:nil];
    }
    if (key.length != 32) {
        @throw [NSException exceptionWithName:CipherException reason:@"AES key should be 256 bits." userInfo:nil];
    }
    if (iv.length != 16) {
        @throw [NSException exceptionWithName:CipherException reason:@"AES-CBC IV should be 128 bits." userInfo:nil];
    }

    size_t bufferSize;
    ows_add_overflow(data.length, kCCBlockSizeAES128, &bufferSize);
    
    NSMutableData *_Nullable bufferData = [NSMutableData dataWithLength:bufferSize];
    OWSAssert(bufferData != nil);

    size_t bytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
        kCCAlgorithmAES128,
        kCCOptionPKCS7Padding,
        [key bytes],
        [key length],
        [iv bytes],
        [data bytes],
        [data length],
        bufferData.mutableBytes,
        bufferSize,
        &bytesDecrypted);

    if (cryptStatus == kCCSuccess) {
        OWSLogDebug(@"throws_decryptCBCMode bufferData: %ld", bufferData.length);
        OWSLogDebug(@"throws_decryptCBCMode bytesDecrypted: %ld", bytesDecrypted);
        NSLog(@"throws_decryptCBCMode bufferData: %ld", bufferData.length);
        NSLog(@"throws_decryptCBCMode bytesDecrypted: %ld", bytesDecrypted);
        NSData *res = [bufferData subdataWithRange:NSMakeRange(0, bytesDecrypted)];
        NSLog(@"throws_decryptCBCMode after: %ld", res.length);
        OWSLogDebug(@"throws_decryptCBCMode after: %ld", res.length);
        return res;
    } else {
        @throw [NSException exceptionWithName:CipherException
                                       reason:@"We encountered an issue while decrypting."
                                     userInfo:nil];
    }
}

@end

NS_ASSUME_NONNULL_END

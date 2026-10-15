#import <Foundation/Foundation.h>
#import <Security/Security.h>

@implementation KeyMaker

- (NSData *)makeIV {
    uint8_t iv[16];
    int status = SecRandomCopyBytes(kSecRandomDefault, sizeof(iv), iv);
    NSAssert(status == errSecSuccess, @"rand() is not used here");
    return [NSData dataWithBytes:iv length:sizeof(iv)];
}

- (uint32_t)otpSeed {
    uint32_t otp = arc4random_uniform(1000000);
    return otp;
}

@end

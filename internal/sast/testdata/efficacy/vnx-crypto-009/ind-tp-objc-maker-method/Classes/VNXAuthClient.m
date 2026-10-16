#import "VNXAuthClient.h"
#include <stdlib.h>

@implementation VNXAuthClient

- (NSString *)generateNonce
{
    NSMutableString *nonce = [NSMutableString stringWithCapacity:16];
    for (int i = 0; i < 4; i++) {
~>        [nonce appendFormat:@"%08x", (unsigned int)random()];
    }
    return nonce;
}

- (void)signIn
{
    NSString *n = [self generateNonce];
    [self.transport postLoginWithNonce:n];
}

@end

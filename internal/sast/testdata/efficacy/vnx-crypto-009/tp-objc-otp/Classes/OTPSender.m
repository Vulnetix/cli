#import <Foundation/Foundation.h>
#include <stdlib.h>

@implementation OTPSender

- (void)sendCodeTo:(NSString *)phone {
~>    NSString *otp = [NSString stringWithFormat:@"%06d", rand() % 1000000];
    [self.gateway send:otp to:phone];
}

@end

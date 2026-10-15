#import <Foundation/Foundation.h>
#include <stdlib.h>

@implementation PasswordReset

- (NSString *)issueToken {
~>    NSString *resetToken = [NSString stringWithFormat:@"%08x%08x", rand(), rand()];
    [self.store saveToken:resetToken];
    return resetToken;
}

@end

#import <Foundation/Foundation.h>
#include <stdlib.h>

@implementation Session

- (NSString *)generateSessionId
{
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 16; i++) {
~>        [s appendFormat:@"%02x", (unsigned int)(random() & 0xff)];
    }
    return s;
}

- (NSInteger)retryDelay {
    return 100 + rand() % 50;
}

@end

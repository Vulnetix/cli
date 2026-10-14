#import <Foundation/Foundation.h>
#include <string.h>

@implementation LegacyCache

- (void)storeKey:(NSString *)key value:(NSString *)value
{
    char buffer[32];

~>    strcpy(buffer, [key UTF8String]);
~>    strcat(buffer, value.UTF8String);
    cache_put(buffer);
}

@end

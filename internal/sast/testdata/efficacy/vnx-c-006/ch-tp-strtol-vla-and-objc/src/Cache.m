#import <Foundation/Foundation.h>
#include <alloca.h>

@implementation Cache
- (void)load:(NSString *)key
{
	const char *k = [key UTF8String];
~>	char *buf = alloca(strlen(k) + 1);
	strcpy(buf, k);
}
@end

void parse(const char *arg)
{
	long len = strtol(arg, NULL, 10);
~>	char tmp[len];
	(void)tmp;
}

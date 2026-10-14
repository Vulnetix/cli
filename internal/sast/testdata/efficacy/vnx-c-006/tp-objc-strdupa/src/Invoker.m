#import <Foundation/Foundation.h>
#include <string.h>

@implementation Invoker

- (void)invoke:(NSInvocation *)invocation
{
    NSUInteger size = invocation.methodSignature.methodReturnLength;
~>    void *result = alloca(size);
    [invocation getReturnValue:result];
}

@end

void normalise(const char *input)
{
~>    char *work = strdupa(input);
    lower(work);
}

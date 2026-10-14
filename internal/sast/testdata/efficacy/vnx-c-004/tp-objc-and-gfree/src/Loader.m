#import <Foundation/Foundation.h>
#include <glib.h>

@implementation Loader

- (void)releaseBuffer:(char *)bytes length:(size_t)length
{
    free(bytes);
~>    NSLog(@"%zu", strlen(bytes));
}

@end

void drop_label(gchar *label)
{
    g_free(label);
~>    g_print("%s\n", label);
}

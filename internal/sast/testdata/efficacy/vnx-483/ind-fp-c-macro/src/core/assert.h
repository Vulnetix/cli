#ifndef CORE_ASSERT_H
#define CORE_ASSERT_H

#define CHECK(x) \
    if (!(x)) \
        report_failure(#x, __FILE__, __LINE__); \
        abort_soon();

#ifdef DEBUG
    #define TRACE(msg) log_msg(msg)
#else
    #define TRACE(msg)
#endif

#endif

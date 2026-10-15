#include <gtest/gtest.h>
__attribute__((no_stack_protector)) static void smash(char *b) { b[64] = 1; }
TEST(Parser, Overflow) { char b[8]; smash(b); }

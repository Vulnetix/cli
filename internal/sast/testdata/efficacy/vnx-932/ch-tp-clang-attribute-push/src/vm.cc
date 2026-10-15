#include <cstddef>

~>#pragma clang attribute push (__attribute__((no_stack_protector)), apply_to = function)
void interp_loop(unsigned char *code, std::size_t n);
void interp_step(unsigned char *code);
#pragma clang attribute pop

~>#pragma GCC optimize ("O3,no-stack-protector")

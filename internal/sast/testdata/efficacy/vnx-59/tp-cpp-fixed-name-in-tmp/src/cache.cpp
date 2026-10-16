#include <cstdio>
#include <fstream>

void Cache::flush() {
    std::FILE *f = std::fopen("/tmp/cache.bin", "wb");
    std::fwrite(buf_.data(), 1, buf_.size(), f);
    std::fclose(f);
~>    std::ofstream out("/tmp/cache.idx");
    out << index_;
}

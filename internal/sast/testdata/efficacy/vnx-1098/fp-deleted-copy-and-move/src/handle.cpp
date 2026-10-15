#include <cstdio>

class FileHandle {
public:
    explicit FileHandle(const char* p) : f_(new FILE*(std::fopen(p, "r"))) {}
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    ~FileHandle() { delete f_; }

private:
    FILE** f_;
};

class Arena {
public:
    Arena() : mem_(new char[4096]) {}
    Arena(Arena&& other) noexcept : mem_(other.mem_) { other.mem_ = nullptr; }
    ~Arena() { delete[] mem_; }

private:
    char* mem_;
};

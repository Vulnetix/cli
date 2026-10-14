#pragma once
#include <memory>

class Codec {
public:
    virtual ~Codec() = default;
    virtual std::size_t encode(const char* in, char* out) = 0;
};

class GzipCodec : public Codec {
public:
    GzipCodec();
~>    ~GzipCodec();
    std::size_t encode(const char* in, char* out) override;
private:
    void* stream_;
};

struct NullCodec final : Codec {
~>  ~NullCodec() noexcept {}
  std::size_t encode(const char*, char*) override { return 0; }
};

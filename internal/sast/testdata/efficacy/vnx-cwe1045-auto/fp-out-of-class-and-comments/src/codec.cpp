#include "codec.hpp"

class Codec {
public:
    virtual ~Codec() = default;
};

class GzipCodec : public Codec {
public:
    // ~GzipCodec(); is declared below with override
    ~GzipCodec() override;
};

GzipCodec::~GzipCodec() {
    release();
}

#pragma once

class Codec {
public:
    virtual ~Codec() = default;
    virtual int encode(const char *in) = 0;
};

class GzipCodec : public Codec {
public:
    int encode(const char *in) override;
~>    ~GzipCodec();
};

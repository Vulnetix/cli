#pragma once

class Codec {
public:
    virtual ~Codec() = default;
    virtual int encode() = 0;
};

class GzipCodec : public Codec {
public:
    int encode() override { return 1; }
};

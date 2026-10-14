#pragma once

class Codec {
public:
    virtual ~Codec() = default;
};

class GzipCodec : public Codec {
public:
    ~GzipCodec() override;
};

class ZstdCodec : public Codec {
public:
    virtual ~ZstdCodec();
};

class LzCodec : public Codec {
public:
    ~LzCodec() noexcept override = default;
};

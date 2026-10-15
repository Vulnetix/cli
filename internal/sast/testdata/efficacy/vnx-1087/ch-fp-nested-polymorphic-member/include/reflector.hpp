#pragma once

struct Reflector {
    struct Tracer {
        virtual ~Tracer() = default;
        virtual void name(const char* n) = 0;
        virtual void field(const char* k, int v) = 0;
    };

    explicit Reflector(Tracer& t) : tracer_(t) {}
    void run();

private:
    Tracer& tracer_;
};

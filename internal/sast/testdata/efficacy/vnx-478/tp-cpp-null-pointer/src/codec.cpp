#include <string>

struct Codec;
Codec *make_gzip();
Codec *make_zstd();

Codec *pick(int kind)
{
    Codec *codec = nullptr;
~>    switch (kind) {
        case 1: codec = make_gzip(); break;
        case 2: codec = make_zstd(); break;
    }
    codec->reset();
    return codec;
}

#include <stddef.h>
#include "codec.h"

const struct codec *codec_for(int id)
{
    const struct codec *c = NULL;

    switch (id) {
    case CODEC_GZIP: c = &gzip_codec; break;
    case CODEC_ZSTD: c = &zstd_codec; break;
    }
    if (c == NULL)
        return &identity_codec;
    return c;
}

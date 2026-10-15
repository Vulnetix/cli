#include <stdio.h>

void codec_shutdown(struct codec *ctx)
{
    if (codec_deinit(ctx) != 0) {
        fprintf(stderr, "codec_deinit failed, continuing shutdown\n");
    }
    if (!sensor_uninit(ctx->sensor))
        fprintf(stderr, "sensor_uninit failed\n");
    free(ctx);
}

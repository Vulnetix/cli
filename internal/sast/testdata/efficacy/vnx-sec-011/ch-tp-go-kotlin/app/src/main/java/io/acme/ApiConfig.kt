package io.acme

object ApiConfig {
    const val BASE_URL = "https://api.acme.io"
~>    private const val DEVICE_TOKEN = "@@sample:e[y]JhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9[.]eyJhdWQiOiJtb2JpbGUiLCJzdWIiOiJkZXZpY2UtNyIsImlhdCI6MTcwMDAwMDAwMH0[.]Gyf3v[-]9NLiDzwPC9JKzx4QjN2ML9cdaZpB39AX5SKAY@@"
    fun header() = "Bearer $DEVICE_TOKEN"
}

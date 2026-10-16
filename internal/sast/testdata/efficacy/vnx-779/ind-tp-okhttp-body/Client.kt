import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor

val client = OkHttpClient.Builder()
~>    .addInterceptor(HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY))
    .build()

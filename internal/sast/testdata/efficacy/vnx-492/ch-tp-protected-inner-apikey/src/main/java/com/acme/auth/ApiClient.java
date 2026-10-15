package com.acme.auth;

public class ApiClient {
    private String apiKey;
    private String baseUrl;

    public ApiClient(String apiKey, String baseUrl) {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }

~>    class AuthInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request r = chain.request().newBuilder()
                    .header("Authorization", "Bearer " + ApiClient.this.apiKey)
                    .build();
            return chain.proceed(r);
        }
    }
}

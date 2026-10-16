#include <stdio.h>
#include <curl/curl.h>

void fetcher_start(void)
{
    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
~>    if (rc != CURLE_OK) {
        fprintf(stderr, "curl_global_init: %s\n", curl_easy_strerror(rc));
    }
    start_worker_threads();
}

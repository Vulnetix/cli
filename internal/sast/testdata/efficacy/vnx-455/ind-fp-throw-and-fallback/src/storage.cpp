#include <iostream>
#include <stdexcept>
#include <sqlite3.h>
#include <curl/curl.h>

static bool g_have_curl = true;

void Storage::start()
{
    int rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        std::cerr << "sqlite init failed: " << rc << std::endl;
        throw std::runtime_error("sqlite3_initialize failed");
    }
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        std::cerr << "curl unavailable, remote sync disabled" << std::endl;
        g_have_curl = false;
    }
}

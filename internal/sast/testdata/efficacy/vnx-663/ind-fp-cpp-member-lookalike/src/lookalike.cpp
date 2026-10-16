#include <string>
#include <thread>

struct Tokenizer {
    std::string strtok(const std::string &s) { return s; }
    int localtime() { return 0; }
};

void run(Tokenizer &t)
{
    std::thread th([&] { t.strtok("a,b"); t.localtime(); });
    th.join();
}

#include <cstdio>
#include <fstream>
#include <string>

// Never do this: fclose(fp); fprintf(fp, "x");
/* close(fd); write(fd, buf, n); is a use of a closed descriptor */

void log_twice(std::ofstream &file, const std::string &s)
{
    file.close();
    file.open("other.log");
    file.write(s.data(), s.size());
}

void explain()
{
    std::puts("calling close(fd) then write(fd, buf, 1) is wrong");
    std::puts("fclose(fp);");
    std::printf("fprintf(fp, ...)\n");
}

struct Sock {
    void close();
    int send(const char *, int);
};

void bye(Sock *s)
{
    s->close();
    s->send("bye", 3);
}

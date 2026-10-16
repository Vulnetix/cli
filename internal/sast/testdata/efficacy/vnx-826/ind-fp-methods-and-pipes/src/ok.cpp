#include <fstream>
#include <unistd.h>

void h(int pipefd[2])
{
    std::ofstream file("a");
    file.close();
    file << "x";
    close(pipefd[1]);
    read(pipefd[0], nullptr, 0);
    // fclose(out); fprintf(out, "x");
    const char *s = "close(sock); recv(sock, b, 1, 0);";
    (void)s;
}

class Conn {
public:
    void shut() { close(fd_); }
    void send_one() { write(fd_, "x", 1); }
private:
    int fd_;
};

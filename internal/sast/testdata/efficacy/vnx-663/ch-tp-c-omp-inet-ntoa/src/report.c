#include <arpa/inet.h>
#include <stdio.h>

void report(struct sockaddr_in *peers, int n) {
    #pragma omp parallel for
    for (int i = 0; i < n; i++) {
~>        printf("%s\n", inet_ntoa(peers[i].sin_addr));
    }
}

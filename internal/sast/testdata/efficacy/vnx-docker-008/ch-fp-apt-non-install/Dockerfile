FROM debian:bookworm-slim
RUN apt-get update && apt-get upgrade -y && apt-get remove -y curl && apt-get purge -y wget
RUN apt-get install -y ./vendor/@@sample:t[o]ol[_]1[.][2][.]3[_]am[d]64[.]de[b]@@
RUN apt-get install -y --no-install-recommends $(cat /tmp/packages.txt)
RUN yum install -y https://repo.example.com/el9/@@sample:a[g]en[t][-]1[.]0[-][1][.]x[8]6[_][6]4[.][r]pm@@

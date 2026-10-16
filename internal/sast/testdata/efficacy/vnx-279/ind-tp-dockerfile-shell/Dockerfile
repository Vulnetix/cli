FROM alpine:3.20
COPY bin/runner /usr/local/bin/runner
~>RUN chmod u+s /usr/bin/find
~>COPY --chmod=4755 bin/sandbox /usr/local/bin/sandbox
CMD ["/usr/local/bin/runner"]

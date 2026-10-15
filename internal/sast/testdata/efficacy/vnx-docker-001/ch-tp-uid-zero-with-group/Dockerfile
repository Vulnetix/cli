FROM debian:bookworm-slim
RUN groupadd -g 1000 app
COPY app /usr/local/bin/app
~>USER 0:1000
CMD ["/usr/local/bin/app"]

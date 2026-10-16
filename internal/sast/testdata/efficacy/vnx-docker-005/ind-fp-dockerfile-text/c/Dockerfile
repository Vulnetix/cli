FROM docker:27.1-cli
# do not use docker run --privileged here
RUN echo "docker run --privileged is dangerous"
CMD ["docker", "run", "--privileged=false", "alpine:3.20"]
LABEL description="never pass --privileged"

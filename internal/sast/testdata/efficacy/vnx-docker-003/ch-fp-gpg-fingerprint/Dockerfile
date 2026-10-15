FROM debian:bookworm-slim
ENV GPG_KEY=@@sample:A[0]35[C]8C[1]92[1]9B[A]82[1]EC[E]A8[6]B6[4]E6[2]8F[8]D6[8]46[9]6D@@
ENV PYTHON_VERSION=3.12.4
RUN gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"

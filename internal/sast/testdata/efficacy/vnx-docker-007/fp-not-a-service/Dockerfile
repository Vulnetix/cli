# CLI image: runs once and exits, nothing to probe
FROM rust:1.79-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=build /src/target/release/rgx /usr/local/bin/rgx
ENTRYPOINT ["/usr/local/bin/rgx"]
CMD ["--help"]

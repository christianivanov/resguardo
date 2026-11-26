# Resguardo container image (milestone M6.6). Two runtime targets:
#   runtime  the resguardo binary only, as a non-root user (the published image);
#   lab      the same plus the mock provider, for lab/ (M6.3).
# Image tags checked on Docker Hub on 2026-11-26; Rust matches rust-toolchain.toml (stable 1.100).

FROM rust:1.100-slim-trixie AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p resguardo -p resguardo-mock-upstream \
    && strip target/release/resguardo target/release/mock-upstream

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin resguardo \
    && mkdir /data && chown resguardo:resguardo /data && chmod 700 /data
COPY --from=build /src/target/release/resguardo /usr/local/bin/resguardo
USER resguardo
WORKDIR /data
EXPOSE 8787
ENTRYPOINT ["resguardo"]
CMD ["run", "--config", "/etc/resguardo/resguardo.toml"]

FROM runtime AS lab
COPY --from=build /src/target/release/mock-upstream /usr/local/bin/mock-upstream
# Mount point of the lab volume that holds the application's virtual key.
USER root
RUN mkdir /labkey && chown resguardo:resguardo /labkey
USER resguardo

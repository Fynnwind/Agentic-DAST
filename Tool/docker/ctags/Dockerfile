# Universal Ctags 6.1.0 — the symbol index behind the scoped code extractor.
# Built here rather than pulled: no upstream publishes a pinned arm64-native tag.
# Both halves of the pin (base image + apk package version) are explicit, so the
# build is reproducible and every later run is offline (`--network none`).
#
# - Build once: `docker build --platform linux/arm64 -t dast-ctags:6.1.0 docker/ctags`
# - alpine 3.20's `ctags` is Universal Ctags 6.1.0, the version the extractor's
#   field usage (`--fields=+neKS`, `end:`) was checked against.
FROM alpine:3.20

RUN apk add --no-cache ctags=6.1.20240421.0-r0

# Extractor mounts a target's source read-only at /src and reads the index off
# stdout (the one-shot `docker run --rm` idiom). No entrypoint: the invocation
# stays visible in `code_context.build_command()`.
WORKDIR /src

# syntax=docker/dockerfile:1
# Build context: the image/ folder (docker build -t advisorydeck:local image/).

FROM golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
# Static binary: no cgo, no libc, nothing to load at run time.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/advisorydeck ./cmd/advisorydeck
# The state folder, owned by the non-root user, so a fresh named volume inherits it.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# distroless static: CA certificates and a nonroot user, no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/advisorydeck /advisorydeck
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
# Only /data is written (state.json and the feed cache), so the root filesystem can be
# mounted read-only. The config is mounted read-only at /config/advisorydeck.yml.
VOLUME ["/data"]
HEALTHCHECK --interval=5m --timeout=10s --start-period=2m --retries=2 CMD ["/advisorydeck", "healthcheck"]
ENTRYPOINT ["/advisorydeck"]
CMD ["run"]

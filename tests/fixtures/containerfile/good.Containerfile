# syntax=docker/dockerfile:1.10
# A Containerfile that passes every check: pinned bases, multi-stage, no credentials, non-root, health check.
FROM registry.access.redhat.com/ubi9/go-toolset:1.24@sha256:0d4bb6b5d1fd8f2bd4c5d2f0e7b1a7f3b2a1c0d9e8f7a6b5c4d3e2f1a0b9c8d7 AS build
WORKDIR /opt/app-root/src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /tmp/app ./cmd/app

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6@sha256:0d4bb6b5d1fd8f2bd4c5d2f0e7b1a7f3b2a1c0d9e8f7a6b5c4d3e2f1a0b9c8d7
RUN microdnf install -y ca-certificates tzdata \
    && microdnf clean all
COPY --from=build /tmp/app /usr/local/bin/app
RUN chgrp 0 /usr/local/bin/app && chmod g=u /usr/local/bin/app
USER 1001
EXPOSE 8080
HEALTHCHECK --interval=30s CMD ["/usr/local/bin/app", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/app"]

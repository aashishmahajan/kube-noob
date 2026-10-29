FROM registry.access.redhat.com/ubi9/go-toolset:1.24@sha256:0d4bb6b5d1fd8f2bd4c5d2f0e7b1a7f3b2a1c0d9e8f7a6b5c4d3e2f1a0b9c8d7
WORKDIR /opt/app-root/src
COPY . .
RUN go build -o /opt/app-root/app ./cmd/app
USER 1001
HEALTHCHECK CMD ["/opt/app-root/app", "healthcheck"]
ENTRYPOINT ["/opt/app-root/app"]

FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6@sha256:0d4bb6b5d1fd8f2bd4c5d2f0e7b1a7f3b2a1c0d9e8f7a6b5c4d3e2f1a0b9c8d7
RUN microdnf install -y shadow-utils && microdnf clean all
USER 1001
HEALTHCHECK CMD ["/bin/true"]
CMD ["/bin/sleep", "infinity"]

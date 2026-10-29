FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
USER 1001
HEALTHCHECK CMD ["/bin/true"]
CMD ["/bin/sleep", "infinity"]

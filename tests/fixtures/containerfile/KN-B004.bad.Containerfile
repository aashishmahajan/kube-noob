FROM registry.access.redhat.com/ubi9/nodejs-20-minimal:1@sha256:0d4bb6b5d1fd8f2bd4c5d2f0e7b1a7f3b2a1c0d9e8f7a6b5c4d3e2f1a0b9c8d7
WORKDIR /opt/app-root/src
COPY .npmrc package.json package-lock.json ./
RUN npm ci --omit=dev
USER 1001
HEALTHCHECK CMD ["node", "healthcheck.js"]
CMD ["node", "server.js"]

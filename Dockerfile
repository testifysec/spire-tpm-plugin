FROM --platform=${BUILDPLATFORM} golang:1.16.4 as build

ARG BINARY
ARG TARGETOS
ARG TARGETARCH

ENV binary_env=$binary

RUN apt update && apt install -y build-essential libtspi-dev && \
    mkdir /app

WORKDIR /app
COPY . .

RUN TARGETOS=${TARGETOS} TARGETARCH=${TARGETARCH} BINARY=${BINARY} make docker-build

FROM --platform=${TARGETPLATFORM} debian:buster-slim

RUN apt update && apt install -y libtspi-dev
WORKDIR /app

ARG BINARY
ENV BINARY_ENV=${BINARY}

COPY --from=build /app/${BINARY_ENV} ./${BINARY_ENV}

ENTRYPOINT ./${BINARY_ENV}

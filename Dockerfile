# This Dockerfile requires DOCKER_BUILDKIT=1 to be build.
# We do not use syntax header so that we do not have to wait
# for the Dockerfile frontend image to be pulled.
FROM golang:1.20-alpine3.18 AS build

RUN apk --update add make git gcc musl-dev
COPY . /go/src/dinit
WORKDIR /go/src/dinit
RUN \
  make build-static && \
  mv dinit /go/bin/dinit

FROM alpine:3.18
RUN apk --update --no-cache add tzdata bash && \
  wget -O /usr/local/bin/regex2json https://gitlab.com/tozd/regex2json/-/releases/v0.1.0/downloads/linux-amd64/regex2json && \
  chmod +x /usr/local/bin/regex2json
COPY --from=build /go/bin/dinit /
ENTRYPOINT ["/dinit"]

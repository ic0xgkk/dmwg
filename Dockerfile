FROM golang:1.22 AS build

ADD . /work
WORKDIR /work

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN go build -v -ldflags="-w -s -buildid=''" -trimpath -o dmwg ./cmd/dmwg

FROM scratch AS export
COPY --from=build /work/dmwg .

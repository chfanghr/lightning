FROM golang:1.16 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
COPY main.go .

RUN CGO_ENABLED=0 go build -o app .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /userdata

COPY --from=builder /app/app /bin/app

VOLUME /userdata

ENTRYPOINT app
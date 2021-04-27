FROM golang:1.16 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY main.go .

RUN CGO_ENABLED=0 go build -v -o app .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /

COPY --from=builder /app/app /bin/app

VOLUME /userdata

ENTRYPOINT app
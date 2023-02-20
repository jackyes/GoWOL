FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN apk update && apk add git gcc build-base
RUN go mod download
RUN  CGO_ENABLED=1 go build -o GoWOL .
FROM alpine:latest
RUN apk update && apk upgrade && rm -rf /var/cache/*
WORKDIR /root/
COPY . .
COPY --from=builder /app/GoWOL .
EXPOSE 8080
CMD ["./GoWOL"]

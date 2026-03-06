FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go .

RUN CGO_ENABLED=0 GOOS=linux go build -o go-wallet .

FROM alpine:3.21

WORKDIR /app
COPY --from=builder /app/go-wallet .
COPY templates/ templates/
RUN mkdir -p /app/data

EXPOSE 7111
ENTRYPOINT ["./go-wallet"]

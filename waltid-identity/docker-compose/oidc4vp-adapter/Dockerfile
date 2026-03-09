FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go .

RUN CGO_ENABLED=0 GOOS=linux go build -o oidc4vp-adapter .

FROM alpine:3.21

WORKDIR /app
COPY --from=builder /app/oidc4vp-adapter .
COPY templates/ templates/

EXPOSE 7112
ENTRYPOINT ["./oidc4vp-adapter"]

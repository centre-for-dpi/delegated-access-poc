FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod .
COPY *.go .

RUN CGO_ENABLED=0 GOOS=linux go build -o status-list-service .

FROM alpine:3.21

RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /app/status-list-service .
COPY templates/ templates/
RUN mkdir -p /app/data && chown appuser:appgroup /app/data

USER appuser

EXPOSE 7006
ENTRYPOINT ["./status-list-service"]

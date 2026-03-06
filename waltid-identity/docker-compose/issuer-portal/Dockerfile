FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go .

RUN CGO_ENABLED=0 GOOS=linux go build -o issuer-portal .

FROM alpine:3.21

WORKDIR /app
COPY --from=builder /app/issuer-portal .
COPY templates/ templates/
RUN mkdir -p /app/data

EXPOSE 7107
ENTRYPOINT ["./issuer-portal"]

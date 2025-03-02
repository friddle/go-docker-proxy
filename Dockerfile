FROM docker.io/library/golang AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o docker-proxy

FROM docker.io/library/alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/docker-proxy .

ENV CUSTOM_DOMAIN=""
ENV MODE="production"
ENV TARGET_UPSTREAM=""
ENV PORT="5000"

EXPOSE ${PORT}

CMD ["./docker-proxy"] 
FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache build-base git
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /out/kosiro-agent ./cmd/agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget docker-cli docker-cli-compose
WORKDIR /app
COPY --from=build /out/kosiro-agent /usr/local/bin/kosiro-agent
ENV KOSIRO_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/kosiro-agent"]

FROM golang:1.26.6-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o blackradar .

FROM alpine:3.24

WORKDIR /app
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates && update-ca-certificates
RUN addgroup -S blackradar && adduser -S -G blackradar blackradar
COPY --from=build /app/blackradar /app/blackradar
USER blackradar

EXPOSE 8080
CMD ["/app/blackradar"]

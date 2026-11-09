FROM golang:1.19-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/ingest .

FROM alpine:3.16
COPY --from=build /out/ingest /usr/local/bin/ingest
ENTRYPOINT ["/usr/local/bin/ingest"]

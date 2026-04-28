FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mock-as main.go

FROM alpine:3.21
COPY --from=build /mock-as /mock-as
EXPOSE 9090
ENTRYPOINT ["/mock-as"]

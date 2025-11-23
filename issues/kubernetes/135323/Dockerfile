FROM golang:1.25.3 AS base

COPY query.go /go

WORKDIR /go

RUN go build query.go

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=base /go/query /query

CMD [ "/query" ]


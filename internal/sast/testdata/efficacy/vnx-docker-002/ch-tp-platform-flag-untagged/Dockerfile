~>FROM --platform=$BUILDPLATFORM golang AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]

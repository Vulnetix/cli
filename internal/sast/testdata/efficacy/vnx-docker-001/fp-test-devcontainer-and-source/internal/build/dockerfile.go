package build

// defaultTemplate is rendered into the user's project by `init`.
const defaultTemplate = `FROM alpine:3.20
COPY app /app
CMD ["/app"]
`

func Template() string { return defaultTemplate }

package pb

type Config struct {
	Name     string
	Port     int
	Host     string
	Timeout  time.Duration
	Verbose  bool
	Retries  int
	Ratio    float64
	Tags     []string
	Labels   map[string]string
	Key      []byte
	Err      error
	Started  time.Time
	Client   *http.Client
	Store    Store
}

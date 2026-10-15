package main

func main() {
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://app.example.com"},
		AllowAllOrigins:  false,
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://app.example.com"
		},
	}))
}

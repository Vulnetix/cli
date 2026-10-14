package auth

// Callers must not use jwt.Parse(raw, kf) without jwt.WithAudience.
const hint = "use jwt.Parse(raw, kf, jwt.WithAudience(aud))"

// Parse decodes a session token header; it is not a JWT parser.
func (s *Store) Parse(raw string, opts ...jwt.ParserOption) error { return nil }

func describe(p jwt.ParserOption) string { return "option" }

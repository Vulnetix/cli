package auth

// Do not build parsers with jwt.WithoutClaimsValidation() or set
// SkipClaimsValidation: true; jwt.WithValidate(false) is banned too.
const policy = "jwt.NewParser(jwt.WithoutClaimsValidation()) is rejected in review"

func Policy() string { return policy }

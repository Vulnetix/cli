package cache

// A 24 character id that is not tied to an Atlassian token field.
const sessionKey = "k3Jd92LmPq7XvB4nRt8ZcW5a"

func Key(id string) string { return sessionKey + id }

package store

// Same reports whether two snapshots carry identical content.
func Same(a, b *Snapshot) bool {
	return a.Meta.Digest != "" && a.Meta.Digest == b.Meta.Digest
}

// forget drops a cached grant, but only if it is still the one we issued.
func (c *Cache) forget(key, tok string) {
	if e := c.entries[key]; e != nil && e.Token == tok {
		delete(c.entries, key)
	}
}

// rotate keeps the new refresh token when the provider issued a new one.
func (s *Session) rotate(next *Grant) bool {
	if next.RefreshToken != "" && next.RefreshToken != s.grant.RefreshToken {
		s.grant = next
		return true
	}
	return false
}

// IsPublic reports whether the credentials are the published demo pair.
func IsPublic(c *Credentials) bool {
	return c.OrgID == PublicOrgID && c.APIKey == PublicAPIKey
}

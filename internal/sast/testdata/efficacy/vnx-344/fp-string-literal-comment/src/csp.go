package src

// Never ship a static policy like "script-src 'nonce-abc123'": generate it per response.
/*
 * Example: Content-Security-Policy: script-src '@@sample:n[o]nc[e][-]E[D]Nn[f]03[n]ce[I]Of[n]39[f]n3[e]9h[3]sd[f]a@@'
 */
func policy(nonce string) string {
	return "script-src 'nonce-" + nonce + "'"
}

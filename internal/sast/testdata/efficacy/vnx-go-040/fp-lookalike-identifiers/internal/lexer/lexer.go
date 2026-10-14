package lexer

import "log"

func (p *Pager) next(nextPageToken string, tokenCount, maxTokens int) {
	log.Printf("fetching page %s", nextPageToken)
	log.Printf("used %d of %d tokens", tokenCount, maxTokens)
	log.Printf("tokens: %v", p.tokens)
	log.Printf("password policy: %+v", p.passwordPolicy)
	log.Printf("min length %d", p.passwordMinLength)
}

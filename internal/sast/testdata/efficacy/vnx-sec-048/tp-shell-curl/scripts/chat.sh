curl https://api.openai.com/v1/chat/completions \
~>  -H "Authorization: Bearer @@sample:sk-proj-[A-Z]{4}[0-9]{4}[a-z]{4}[A-Za-z0-9_-]{100}@@" \
  -d '{"model": "gpt-4o"}'

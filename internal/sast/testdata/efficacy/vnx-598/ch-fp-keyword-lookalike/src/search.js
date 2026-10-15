async function search(keyword, page) {
  const res = await fetch(`/api/search?keyword=${encodeURIComponent(keyword)}&page=${page}`);
  const monkey = await fetch(`/api/zoo?monkey=${keyword}&tokenizer=${page}`);
  return [res, monkey];
}

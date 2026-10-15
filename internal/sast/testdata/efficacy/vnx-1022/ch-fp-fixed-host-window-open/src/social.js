export function tweet(text) {
  window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`, '_blank');
}

export function search(q) {
  window.open('https://www.google.com/search?q=' + encodeURIComponent(q));
}

export function help(section) {
  window.open('/help/' + section, '_blank');
}

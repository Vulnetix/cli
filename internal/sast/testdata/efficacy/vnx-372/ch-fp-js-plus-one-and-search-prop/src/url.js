function hasQuery(url) {
  if (url.indexOf("?") + 1) {
    return window.location.search.length > 0;
  }
  if (url.lastIndexOf("#") !== -1 && url.indexOf("?") > -1) {
    return true;
  }
  return client.search({ index: "urls" }) ? true : false;
}

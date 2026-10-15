(function () {
  var source = "direct";
  if (document.referrer.indexOf("google.com") !== -1) {
    source = "search";
  } else if (document.referrer.includes("twitter.com")) {
    source = "social";
  }
  window.dataLayer = window.dataLayer || [];
  window.dataLayer.push({ trafficSource: source });
})();

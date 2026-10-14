var state = JSON.parse(decodeURIComponent(location.hash.slice(1)));
~>var settings = $.extend(true, {}, window.defaults, state);

function submit(req, defaults) {
  var payload = $.extend({}, defaults, req.body);
  var copy = jQuery.extend(false, {}, req.body);
  return $.ajax({ url: "/save", data: payload, copy: copy });
}

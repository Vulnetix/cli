function hide(elems, orig) {
  var prop;
  for (prop in orig) {
    elems.done(function () {
      for (prop in orig) {
        reset(prop);
      }
    });
  }
}

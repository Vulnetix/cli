for (var i = 0; i < jobs.length; i++) {
  jobs[i].onDone(function () {
    for (var i = 0; i < 3; i++) {
      log(i);
    }
  });
}

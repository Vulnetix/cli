$(function () {
  $('#go').on('click', function () {
    var q = $('#q').val();
    $.get('/search?q=' + encodeURIComponent(q), function (data) { $('#results').html(data); });
    document.title = 'Results for ' + encodeURIComponent(q);
  });
});

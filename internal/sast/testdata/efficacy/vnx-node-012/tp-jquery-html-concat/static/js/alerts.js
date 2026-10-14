$(function () {
  $.getJSON('/api/notice', function (res) {
~>    $('#alert').html('<p class="warn">' + res.message + '</p>');
  });

  var name = new URLSearchParams(location.search).get('name');
~>  $('#greeting').html(name);

~>  $('.status').html(
    '<b>' + localStorage.getItem('status') + '</b>'
  );
});

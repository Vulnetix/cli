$(function () {
  $('#q').on('input', function () {
    var term = $(this).val();
~>    $('#echo').html('<li>' + encodeURIComponent(term) + '</li>');
  });
});

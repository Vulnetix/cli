function showWarning(res) {
~>  $('#alert').html('<p class="warn">' + res.message + '</p>');
}
$.getJSON('/api/status', showWarning);

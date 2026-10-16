function init() {
  $('#empty').html('<p>No results</p>');
  const current = $('#panel').html();
  $('#label').text(current);
  document.getElementById('n').textContent = location.hash;
}

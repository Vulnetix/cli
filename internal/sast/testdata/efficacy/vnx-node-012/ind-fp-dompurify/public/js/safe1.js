function render(res) {
  $('#out').html(DOMPurify.sanitize(res.message));
}

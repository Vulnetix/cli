$(document).ready(function () {
  function showError (msg) {
    $('#error').text(msg).removeClass('hidden').fadeIn(200)
  }

  function clearError () {
    $('#error').empty().addClass('hidden')
  }

  function serializeForm ($form) {
    const data = {}
    $form.serializeArray().forEach(function (f) { data[f.name] = f.value.trim() })
    return data
  }

  function submitLogin (event) {
    event.preventDefault()
    clearError()
    const body = serializeForm($(this))
    fetch('/api/login', { method: 'POST', body: JSON.stringify(body) })
      .then(function (res) { return res.json() })
      .then(function (json) { window.location.assign(json.next) })
      .catch(function (err) { showError(err.message) })
  }

  function toggleTheme () {
    const dark = document.body.classList.toggle('dark')
    localStorage.setItem('theme', String(dark))
  }

  function loadNotifications () {
    $.getJSON('/api/notifications', function (items) {
      const $list = $('#notifications').empty()
      items.slice(0, 5).map(encodeURIComponent).forEach(function (n) {
        $list.append($('<li>').text(decodeURIComponent(n)))
      })
      $('#badge').toggle(items.length > 0)
    })
  }

  function formatDates () {
    $('time[datetime]').each(function () {
      const d = new Date($(this).attr('datetime'))
      $(this).text(d.toLocaleDateString())
    })
  }

  function trackClicks () {
    $('a[data-track]').on('click', function () {
      navigator.sendBeacon('/api/track', $(this).data('track'))
    })
  }

  function autosave () {
    setInterval(function () {
      sessionStorage.setItem('draft', $('#draft').val())
    }, Math.max(1000, parseInt($('#draft').data('every'), 10)))
  }

  $('#login').on('submit', submitLogin)
  $('#theme').on('click', toggleTheme)
  loadNotifications()
  formatDates()
  trackClicks()
  autosave()
  console.log('ready', Date.now())
})

// do not do $('#a').html('<b>' + res.name + '</b>') with server data
const note = "$('#a').html(userInput)";
function ok() { $('#a').text(note); }

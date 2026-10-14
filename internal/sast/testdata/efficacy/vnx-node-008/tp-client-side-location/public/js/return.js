const params = new URLSearchParams(window.location.search);
const back = params.get('return');
~>window.location.href = back;
~>location.assign(new URLSearchParams(location.search).get('next'));

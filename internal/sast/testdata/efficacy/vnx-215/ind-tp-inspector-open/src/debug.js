const inspector = require('inspector');

process.on('SIGUSR2', () => {
~>  inspector.open(9229, '0.0.0.0');
  console.log('inspector listening on', inspector.url());
});

const inspector = require('inspector');
~>inspector.open(9229, '0.0.0.0');
require('./app').listen(3000);

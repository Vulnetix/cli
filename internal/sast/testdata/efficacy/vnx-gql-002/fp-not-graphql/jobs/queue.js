const { Producer } = require('./producer');

const producer = new Producer({
  batching: true,
  maxBatchSize: 100,
});
module.exports = producer;

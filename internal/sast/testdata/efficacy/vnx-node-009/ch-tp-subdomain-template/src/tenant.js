const axios = require('axios');

exports.tenantInfo = async (req, res) => {
~>  const { data } = await axios.get(`https://${req.query.tenant}.example.com/api/info`);
  res.json(data);
};

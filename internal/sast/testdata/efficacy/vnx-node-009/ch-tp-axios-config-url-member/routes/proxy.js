const axios = require("axios");

router.post("/preview", async (req, res) => {
~>  const response = await axios({
    url: req.body.link,
    method: "get",
    timeout: 3000,
  });
  res.send(response.data);
});

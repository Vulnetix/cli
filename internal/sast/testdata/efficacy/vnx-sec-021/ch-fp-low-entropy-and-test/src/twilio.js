const twilio = require("twilio");
const authToken = "@@sample:0[0]00[0]00[0]00[0]00[0]00[0]00[0]00[0]00[0]00[0]00[0]@@";
const apiSecret = "your_auth_token_goes_here_please";
module.exports = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

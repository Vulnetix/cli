const { SLACK_TEAM, SLACK_BOT, SLACK_SECRET } = process.env;
const url = `https://hooks.slack.com/services/${SLACK_TEAM}/${SLACK_BOT}/${SLACK_SECRET}`;
module.exports = url;

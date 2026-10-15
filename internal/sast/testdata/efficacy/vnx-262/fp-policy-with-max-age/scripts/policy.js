const { UpdateAccountPasswordPolicyCommand } = require('@aws-sdk/client-iam');
const cmd = new UpdateAccountPasswordPolicyCommand({ MinimumPasswordLength: 14, MaxPasswordAge: 90 });
module.exports = { cmd };

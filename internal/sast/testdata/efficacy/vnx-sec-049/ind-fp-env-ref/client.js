// admin keys start with sk-ant-admin01- and must come from the environment
const key = process.env.ANTHROPIC_ADMIN_KEY;
const prefix = "sk-ant-admin01-";
if (!key || !key.startsWith(prefix)) throw new Error("missing admin key");

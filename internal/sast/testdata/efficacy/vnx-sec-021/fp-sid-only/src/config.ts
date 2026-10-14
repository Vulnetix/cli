// The Account SID is an identifier; the token comes from the vault.
export const TWILIO_ACCOUNT_SID = "AC@@sample:[0-9a-f]{32}@@";
export const authToken = await vault.read("twilio/auth_token");

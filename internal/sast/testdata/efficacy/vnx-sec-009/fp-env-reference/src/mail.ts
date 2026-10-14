import sgMail from "@sendgrid/mail";

const key = process.env.SENDGRID_API_KEY;
if (!key || !key.startsWith("SG.")) {
  throw new Error("SENDGRID_API_KEY must be an SG. key");
}
sgMail.setApiKey(key);

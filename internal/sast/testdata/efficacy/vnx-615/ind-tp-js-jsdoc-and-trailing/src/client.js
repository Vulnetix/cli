/**
 * Calls the billing API.
~> * api_key: 4f9a2c71e8b3d6a0
 */
function call() {
  return fetch(process.env.BILLING_URL); // client_secret = "s3cr3t-Vault#41"
}

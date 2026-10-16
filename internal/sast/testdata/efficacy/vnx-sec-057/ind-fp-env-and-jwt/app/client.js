const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PLFhFs9u1mTc";
const token = process.env.GRAFANA_SA_TOKEN;
if (token.startsWith("glsa_")) {
  console.log("service account token detected");
}
const placeholder = "glsa_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_00000000";
module.exports = { token, jwt };

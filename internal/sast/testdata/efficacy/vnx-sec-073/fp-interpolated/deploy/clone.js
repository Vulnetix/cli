const url = `https://${process.env.GH_USER}:${process.env.GH_TOKEN}@github.com/acme/infra.git`;
const tpl = 'https://{{ .User }}:{{ .Password }}@git.acme-corp.io/infra.git';
module.exports = { url, tpl };

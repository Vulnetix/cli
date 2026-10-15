const url = "postgres://" + process.env.PGUSER + ":" + process.env.PGPASSWORD + "@" + process.env.PGHOST + "/app";
const url2 = `postgresql://${user}:${encodeURIComponent(pass)}@${host}/app`;

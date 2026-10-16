const v = process.env.npm_package_version;
const c = process.env.npm_config_user_agent;
const lifecycle = process.env.npm_lifecycle_event;
console.log(v, c, lifecycle);

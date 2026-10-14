const version = process.env.npm_package_version;
const cache = process.env.npm_config_cache;
const event = process.env.npm_lifecycle_event;
const npm_packageJsonVersionResolverWorkspaces = require("./resolve");
console.log(`installing ${version} via ${event} into ${cache}`);

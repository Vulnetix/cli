// npm exposes package.json fields to lifecycle scripts as npm_package_* vars.
const name = process.env.npm_package_name;
const registry = process.env.npm_config_registry;
const lifecycle = process.env.npm_lifecycle_event_with_a_long_suffix_value;
const tok = process.env.NPM_TOKEN;
console.log(`${name} ${registry} ${lifecycle} ${tok ? "authenticated" : "anonymous"}`);

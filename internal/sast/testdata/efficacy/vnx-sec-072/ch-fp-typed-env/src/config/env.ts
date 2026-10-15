export const apiKey: string = process.env.API_KEY ?? "";
export const clientSecret: string = config.get<string>("clientSecret");
const TOKEN: &str = env!("API_TOKEN");

export const SLACK_API = "https://slack.com/api/chat.postMessage";
export const HOOK_HOST = "https://hooks.slack.com/services/";
export function isBotToken(t: string): boolean {
  return t.startsWith("xoxb-");
}

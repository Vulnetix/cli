const SLACK_PREFIXES = ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"];
export const isSlackHook = (u: string) => u.startsWith("https://hooks.slack.com/services/");

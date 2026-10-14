export async function fetchUsage(): Promise<unknown> {
  const res = await fetch("https://api.anthropic.com/v1/organizations/usage_report/messages", {
    headers: {
~>      "x-api-key": `sk-ant-admin01-@@sample:[A-Za-z0-9]{93}@@AA`,
      "anthropic-version": "2023-06-01",
    },
  });
  return res.json();
}

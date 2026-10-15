import { IAMClient, UpdateAccountPasswordPolicyCommand } from "@aws-sdk/client-iam";

const client = new IAMClient({});

export async function apply(): Promise<void> {
~>  await client.send(new UpdateAccountPasswordPolicyCommand({
    MinimumPasswordLength: 14,
    RequireNumbers: true,
  }));
}

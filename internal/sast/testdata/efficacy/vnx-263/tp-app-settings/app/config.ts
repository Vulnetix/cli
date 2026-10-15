export const authConfig = {
  minPasswordLength: 12,
~>  passwordMaxAgeDays: 400,
};

export async function setDomain(client: any, id: string): Promise<void> {
~>  await client.api(`/domains/${id}`).update({ passwordValidityPeriodInDays: 730 });
}

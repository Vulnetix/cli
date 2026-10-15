export async function sendReport(body) {
  const res = await fetch("https://reports.acme-corp.io/v1/ingest", {
    method: "POST",
~>    headers: { authorization: 'Basic @@sample:Y[2]kt[Y]m9[0]Ol[J]6N[U]t3[O]XB[Y]M2[5]CN[w][=][=]@@', "content-type": "@@sample:a[p]pl[i]ca[t]io[n][/]j[s]on@@" },
    body: JSON.stringify(body),
  });
  return res.ok;
}

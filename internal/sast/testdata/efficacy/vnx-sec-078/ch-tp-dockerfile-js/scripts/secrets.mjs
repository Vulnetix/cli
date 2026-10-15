const res = await fetch('https://api.doppler.com/v3/configs/config/secrets?project=web&config=prd', {
~>  headers: { Authorization: `Bearer @@sample:dp\.pt\.[A-Za-z0-9]{43}@@` },
});
console.log(await res.json());

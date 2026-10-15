curl https://connect.squareup.com/v2/payments \
~>  -H 'Authorization: Bearer @@sample:EAAA[a-z]{3}[0-9]{3}[A-Z]{3}[A-Za-z0-9_-]{51}@@' \
  -H 'Square-Version: 2024-01-18'

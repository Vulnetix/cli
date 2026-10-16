const PRODUCT_FIELDS = `fragment P on Product { id name price }`;
const q = `query { products { ...P } } ${PRODUCT_FIELDS}`;
const limit = parseInt(req.query.limit, 10);
const q2 = `query { products(first: ${limit}) { id } }`;
const q3 = `query { products(filter: ${JSON.stringify(req.body.filter)}) { id } }`;

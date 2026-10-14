const { gql } = require('graphql-tag');
const { apollo } = require('./apollo');

const PRODUCT_FIELDS = gql`
  fragment ProductFields on Product { id title price }
`;

const LIST = gql`
  query {
    products { ...ProductFields }
  }
  ${PRODUCT_FIELDS}
`;

async function page(req) {
  const limit = parseInt(req.query.limit, 10);
  const term = req.query.term;
  const query = `query { products(first: ${limit}) { id } }`;
  const safe = `query { search(term: ${JSON.stringify(term)}) { id } }`;
  // const bad = `query { search(term: "${term}") { id } }`;
  return [await apollo.query({ query: LIST }), query, safe];
}

module.exports = { page };

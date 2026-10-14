import lodash from 'lodash';

export function patch(req, doc) {
~>  lodash.set(doc, req.query.path, req.query.value);
  return doc;
}

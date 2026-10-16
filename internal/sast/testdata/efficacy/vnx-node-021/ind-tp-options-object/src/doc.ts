import { parseXml } from 'libxmljs2';

const opts = {
  huge: false,
~>  noent: true,
};

export const load = (s: string) => parseXml(s, opts);

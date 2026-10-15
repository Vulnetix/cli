import _ from 'lodash';

export function safe(name: string): string {
~>  return _.trimStart(name, './');
}

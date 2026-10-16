~>import { fromB } from './b'

export const fromA = (): string => 'a' + fromB()

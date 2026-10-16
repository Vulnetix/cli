import { fromA } from './a'

export const fromC = (): string => 'c' + fromA()

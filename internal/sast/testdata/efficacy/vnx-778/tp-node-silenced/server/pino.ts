import pino from 'pino'

~>export const log = pino({ level: 'silent' })
~>export const audit = pino({ enabled: false })

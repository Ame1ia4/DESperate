/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
export const shorthands = undefined

export const up = (pgm) => {
  pgm.addColumn('message_hidden', {
    notice_sent: {
      type: 'boolean',
      notNull: true,
      default: false,
    },
  }, { ifNotExists: true })
}

export const down = (pgm) => {
  pgm.dropColumn('message_hidden', 'notice_sent', { ifExists: true })
}

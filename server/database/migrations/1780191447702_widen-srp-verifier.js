/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
export const shorthands = undefined;

export const up = (pgm) => {
  pgm.alterColumn('users', 'srp_verifier', { type: 'VARCHAR(768)' })
}

export const down = (pgm) => {
  pgm.alterColumn('users', 'srp_verifier', { type: 'VARCHAR(512)' })
}

/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
export const shorthands = undefined;

export const up = (pgm) => {
  pgm.dropColumns('devices', ['srp_verified_at', 'srp_expires_at'])
}

export const down = (pgm) => {
  pgm.addColumns('devices', {
    srp_verified_at: { type: 'timestamptz' },
    srp_expires_at:  { type: 'timestamptz' },
  })
}

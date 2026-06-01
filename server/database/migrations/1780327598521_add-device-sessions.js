/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
export const shorthands = undefined;

export const up = (pgm) => {
  pgm.createTable('device_sessions', {
    device_id: {
      type: 'uuid',
      primaryKey: true,
      references: '"devices"',
      onDelete: 'CASCADE',
    },
    session_key_hex: {
      type: 'text',
      notNull: true,
    },
    expires_at: {
      type: 'timestamptz',
      notNull: true,
    },
  }, { ifNotExists: true })

  pgm.createIndex('device_sessions', 'expires_at', {
    name: 'idx_device_sessions_expiry',
    ifNotExists: true,
  })
}

export const down = (pgm) => {
  pgm.dropTable('device_sessions', { ifExists: true })
}

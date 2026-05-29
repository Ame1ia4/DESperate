/**
 * @type {import('node-pg-migrate').ColumnDefinitions | undefined}
 */
export const shorthands = undefined;

/**
 * @param pgm {import('node-pg-migrate').MigrationBuilder}
 * @param run {() => void | undefined}
 * @returns {Promise<void> | void}
 */
export const up = (pgm) => {
  pgm.dropConstraint('srp_challenges', 'srp_challenges_user_id_fkey')
  pgm.renameColumn('srp_challenges', 'user_id', 'device_id')
  pgm.addConstraint('srp_challenges', 'srp_challenges_device_id_fkey',
    'FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE')
}

export const down = (pgm) => {
  pgm.dropConstraint('srp_challenges', 'srp_challenges_device_id_fkey')
  pgm.renameColumn('srp_challenges', 'device_id', 'user_id')
  pgm.addConstraint('srp_challenges', 'srp_challenges_user_id_fkey',
    'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE')
}

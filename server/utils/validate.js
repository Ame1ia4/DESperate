import {
  HEX_RE, UUID_RE,
  USERNAME_MIN, USERNAME_MAX, USERNAME_REGEX,
  SRP_EPHEMERAL_HEX, SRP_EPHEMERAL_HEX_MIN,
} from '../constants/auth.js'

export const isValidUsername = (v) =>
  typeof v === 'string' &&
  v.length >= USERNAME_MIN &&
  v.length <= USERNAME_MAX &&
  USERNAME_REGEX.test(v)

export const isValidUUID = (v) =>
  typeof v === 'string' && UUID_RE.test(v)

export const isValidClientPublicEphemeral = (v) =>
  typeof v === 'string' &&
  v.length >= SRP_EPHEMERAL_HEX_MIN &&
  v.length <= SRP_EPHEMERAL_HEX &&
  HEX_RE.test(v)

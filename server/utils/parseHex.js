// Parse a hex string and verify its decoded length matches expectedBytes.
// Throws a 400 error on any mismatch so callers can return early.
export function parseHex(hex, expectedBytes, fieldName) {
  if (typeof hex !== 'string' || hex.length !== expectedBytes * 2) {
    const err = new Error(`Invalid ${fieldName}`)
    err.status = 400
    throw err
  }
  const buf = Buffer.from(hex, 'hex')
  if (buf.length !== expectedBytes) {
    const err = new Error(`Invalid ${fieldName}`)
    err.status = 400
    throw err
  }
  return buf
}

// Explicit hex check — do not rely on Buffer.from silently truncating invalid input.
const HEX_RE = /^[0-9a-fA-F]*$/

// Parses a hex string and returns a Buffer of exactly expectedBytes.
// Throws a 400 error if the input is not a string, wrong length, or contains non-hex characters.
export function parseHex(hex, expectedBytes, fieldName) {
  if (
    typeof hex !== 'string' ||
    hex.length !== expectedBytes * 2 ||
    !HEX_RE.test(hex)
  ) {
    const err = new Error(`Invalid ${fieldName}`)
    err.status = 400
    throw err
  }
  return Buffer.from(hex, 'hex')
}

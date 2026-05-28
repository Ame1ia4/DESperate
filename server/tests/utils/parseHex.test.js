import { describe, it, expect } from 'vitest'
import { parseHex } from '../../utils/parseHex.js'

describe('parseHex', () => {
  describe('valid input', () => {
    it('parses a valid 32-byte hex string', () => {
      const hex = 'a'.repeat(64)
      const buf = parseHex(hex, 32, 'test')
      expect(buf).toBeInstanceOf(Buffer)
      expect(buf.length).toBe(32)
    })

    it('accepts uppercase hex', () => {
      const hex = 'A'.repeat(64)
      const buf = parseHex(hex, 32, 'test')
      expect(buf.length).toBe(32)
    })

    it('accepts all-zeros hex', () => {
      const hex = '0'.repeat(64)
      const buf = parseHex(hex, 32, 'test')
      expect(buf.every(b => b === 0)).toBe(true)
    })

    it('accepts mixed-case hex', () => {
      const hex = 'aAbBcCdD'.repeat(8)
      const buf = parseHex(hex, 32, 'test')
      expect(buf.length).toBe(32)
    })
  })

  describe('non-string input', () => {
    const cases = [null, undefined, 0, 42, {}, [], true, false, Symbol('x')]
    for (const val of cases) {
      it(`rejects ${String(val)} (type ${typeof val})`, () => {
        expect(() => parseHex(val, 32, 'field')).toThrow()
        try {
          parseHex(val, 32, 'field')
        } catch (err) {
          expect(err.status).toBe(400)
          expect(err.message).toBe('Invalid field')
        }
      })
    }
  })

  describe('wrong length', () => {
    it('rejects hex string one char too short (63 chars for 32 bytes)', () => {
      const hex = 'a'.repeat(63)
      expect(() => parseHex(hex, 32, 'field')).toThrow()
      try { parseHex(hex, 32, 'field') } catch (e) { expect(e.status).toBe(400) }
    })

    it('rejects hex string one char too long (65 chars for 32 bytes)', () => {
      const hex = 'a'.repeat(65)
      expect(() => parseHex(hex, 32, 'field')).toThrow()
      try { parseHex(hex, 32, 'field') } catch (e) { expect(e.status).toBe(400) }
    })

    it('rejects empty string when bytes > 0', () => {
      expect(() => parseHex('', 32, 'field')).toThrow()
      try { parseHex('', 32, 'field') } catch (e) { expect(e.status).toBe(400) }
    })

    it('rejects odd-length hex string (e.g. "abc" for 2 bytes)', () => {
      expect(() => parseHex('abc', 2, 'field')).toThrow()
      try { parseHex('abc', 2, 'field') } catch (e) { expect(e.status).toBe(400) }
    })
  })

  describe('invalid hex content', () => {
    it('rejects a string with non-hex chars at the right length', () => {
      // 64-char string but contains non-hex 'g'
      const hex = 'g'.repeat(64)
      expect(() => parseHex(hex, 32, 'field')).toThrow()
      try { parseHex(hex, 32, 'field') } catch (e) { expect(e.status).toBe(400) }
    })

    it('rejects a string with null byte embedded', () => {
      const hex = '\x00'.repeat(64)
      expect(() => parseHex(hex, 32, 'field')).toThrow()
      try { parseHex(hex, 32, 'field') } catch (e) { expect(e.status).toBe(400) }
    })
  })

  describe('error message', () => {
    it('includes the fieldName in error message', () => {
      try {
        parseHex('not-hex', 32, 'my_special_field')
      } catch (err) {
        expect(err.message).toBe('Invalid my_special_field')
      }
    })
  })
})

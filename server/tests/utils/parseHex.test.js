import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseHex } from '../../utils/parseHex.js'

describe('parseHex', () => {
  describe('valid input', () => {
    it('parses a valid 32-byte hex string', () => {
      const buf = parseHex('a'.repeat(64), 32, 'test')
      assert.ok(buf instanceof Buffer)
      assert.strictEqual(buf.length, 32)
    })

    it('accepts uppercase hex', () => {
      const buf = parseHex('A'.repeat(64), 32, 'test')
      assert.strictEqual(buf.length, 32)
    })

    it('accepts all-zeros hex', () => {
      const buf = parseHex('0'.repeat(64), 32, 'test')
      assert.ok(buf.every(b => b === 0))
    })

    it('accepts mixed-case hex', () => {
      const buf = parseHex('aAbBcCdD'.repeat(8), 32, 'test')
      assert.strictEqual(buf.length, 32)
    })
  })

  describe('non-string input', () => {
    const cases = [null, undefined, 0, 42, {}, [], true, false, Symbol('x')]
    for (const val of cases) {
      it(`rejects ${String(val)} (type ${typeof val})`, () => {
        assert.throws(
          () => parseHex(val, 32, 'field'),
          (err) => {
            assert.strictEqual(err.status, 400)
            assert.strictEqual(err.message, 'Invalid field')
            return true
          }
        )
      })
    }
  })

  describe('wrong length', () => {
    it('rejects hex string one char too short (63 chars for 32 bytes)', () => {
      assert.throws(
        () => parseHex('a'.repeat(63), 32, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })

    it('rejects hex string one char too long (65 chars for 32 bytes)', () => {
      assert.throws(
        () => parseHex('a'.repeat(65), 32, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })

    it('rejects empty string when bytes > 0', () => {
      assert.throws(
        () => parseHex('', 32, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })

    it('rejects odd-length hex string (e.g. "abc" for 2 bytes)', () => {
      assert.throws(
        () => parseHex('abc', 2, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })
  })

  describe('invalid hex content', () => {
    it('rejects a string with non-hex chars at the right length', () => {
      assert.throws(
        () => parseHex('g'.repeat(64), 32, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })

    it('rejects a string with null byte embedded', () => {
      assert.throws(
        () => parseHex('\x00'.repeat(64), 32, 'field'),
        (err) => { assert.strictEqual(err.status, 400); return true }
      )
    })
  })

  describe('error message', () => {
    it('includes the fieldName in error message', () => {
      assert.throws(
        () => parseHex('not-hex', 32, 'my_special_field'),
        (err) => {
          assert.strictEqual(err.message, 'Invalid my_special_field')
          return true
        }
      )
    })
  })
})

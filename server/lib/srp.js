import { createSRPServer } from 'js-srp6a'

// Single shared SRP server instance (SHA-256, RFC 5054 3072-bit group).
// Import this everywhere instead of calling createSRPServer() per-module.
export const srp = createSRPServer('SHA-256', 3072)

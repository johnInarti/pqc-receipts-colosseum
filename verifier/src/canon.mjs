/**
 * RFC 8785 (JCS) canonicalisation — re-exported from Trust Kernel v2 (single implementation, depth/node
 * limited, refuses lone surrogates and non-finite numbers). `jcsSigned` additionally restricts numbers to
 * safe integers (the subset every runtime canonicalises identically; spec §4.3).
 */
export { jcs, jcsSigned, utf8 } from '@fractalai/pqc-trust-kernel';

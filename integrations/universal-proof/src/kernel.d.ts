// Minimal type surface of the Trust Kernel v2 (JavaScript, untyped) used by these adapters.
declare module '@fractalai/pqc-trust-kernel' {
  export type Level = 'integrity' | 'authentic' | 'trusted' | 'time_anchored' | 'finalized' | 'onchain';
  export interface Reason { level: Level; code: string; detail: string }
  export interface Verdict {
    kernel: string;
    spec_version: string;
    kind: string | null;
    valid: boolean;
    levels: Record<Level, boolean | null>;
    trust_basis: 'pinned-root' | 'override' | 'tls' | 'none';
    key: { kid: string; use?: string; status?: string; time_basis?: string } | null;
    signed: Record<string, unknown> | null;
    signed_time: number | null;
    overrides: string[];
    ignored_unsigned_fields: string[];
    reasons: Reason[];
    exit_code: number;
  }
  export interface VerifyOptions {
    kind?: string;
    kinds?: string[];
    expectedId?: string;
    directory?: unknown;
    directoryHistory?: unknown;
    trustedKeys?: string[] | string;
    roots?: unknown;
    governanceKey?: string;
    allowTlsDirectory?: boolean;
    checkAnchors?: boolean;
    anchors?: unknown;
    rpc?: Record<string, string[]>;
    policy?: { require?: Level[]; allowTestnetAnchors?: boolean; maxClockSkewSec?: number };
    now?: number;
    fetchImpl?: typeof fetch;
  }
  export function verify(input: string | Uint8Array | object, opts?: VerifyOptions): Promise<Verdict>;
  export function verifySync(input: string | Uint8Array | object, opts?: VerifyOptions): Verdict;
  export const SPEC_VERSION: string;
  export const COMMERCE_DOMAIN: string;
  export const COMMERCE_VERSION: string;
  export const COMMERCE_MAX_BYTES: number;
  export function checkCommerceBody(body: unknown): number;
  export function commerceSigningMessage(body: unknown): { commerce_id: string; message: string };
  export function jcs(v: unknown): string;
  export function jcsSigned(v: unknown): string;
  export function sha256hex(v: string | Uint8Array): string;
  export function kidForKey(publicKeyB64: string): string;
  export function b64encode(bytes: Uint8Array): string;
  export function directoryRoot(keys: unknown[], prevRoot: string, epoch: number, governanceKeyB64: string): string;
  export const KEY_DIR_DOMAIN: string;
  export const BAKED_ROOTS: Record<string, any>;
}

/**
 * A2A v1 transport for agent-commerce receipts (a2aproject/A2A, specification/a2a.proto v1.0.x).
 *
 * The delivered thing in A2A is an `Artifact` (artifactId, parts[], metadata, extensions[]). The receipt travels
 * IN that artifact, as the A2A extension guide recommends ("custom attributes in the `metadata` map"):
 *   artifact.extensions += [FRACTALAI_A2A_EXTENSION]
 *   artifact.metadata[FRACTALAI_A2A_EXTENSION] = <agent-commerce-receipt>
 * and `delivery.sha256` = sha256(JCS(artifact.parts)) — the receipt binds exactly the parts the client received
 * (metadata, including the receipt itself, is excluded). Agents advertise support in
 * AgentCard.capabilities.extensions[] and clients activate it with the `A2A-Extensions` request header.
 * The URI is FractalAI's own (no permission needed); making it "official" requires the A2A TSC process.
 */
import { jcs, sha256Of } from './core.ts';
import type { CommerceReceipt } from './core.ts';

export const FRACTALAI_A2A_EXTENSION = 'https://fractalai.net.co/a2a/ext/pqc-receipt/v1';

export interface A2APart { text?: string; raw?: string; url?: string; data?: unknown; metadata?: Record<string, unknown>; filename?: string; mediaType?: string }
export interface A2AArtifact { artifactId: string; name?: string; description?: string; parts: A2APart[]; metadata?: Record<string, unknown>; extensions?: string[] }
export interface A2AAgentExtension { uri: string; description?: string; required?: boolean; params?: Record<string, unknown> }

/** AgentCard.capabilities.extensions[] entry an agent publishes to advertise the receipt extension. */
export function agentCardExtension(params: { profiles: string[]; directoryUrl?: string } = { profiles: ['ap2.fulfillment/1'] }, required = false): A2AAgentExtension {
  return {
    uri: FRACTALAI_A2A_EXTENSION,
    description: 'Each delivered Artifact carries a post-quantum (ML-DSA-65) agent-commerce-receipt binding the payment to sha256(JCS(artifact.parts)). Verify with Trust Kernel v2 (spec 2.2, kind agent-commerce-receipt).',
    required,
    params,
  };
}

/** The exact bytes a commerce receipt binds for an A2A artifact. */
export const artifactPartsDigestInput = (a: A2AArtifact): string => jcs(a.parts);
export const artifactDeliverySha256 = (a: A2AArtifact): string => sha256Of(artifactPartsDigestInput(a));

export function attachReceipt(a: A2AArtifact, receipt: CommerceReceipt): A2AArtifact {
  const extensions = [...new Set([...(a.extensions ?? []), FRACTALAI_A2A_EXTENSION])];
  return { ...a, extensions, metadata: { ...(a.metadata ?? {}), [FRACTALAI_A2A_EXTENSION]: receipt } };
}

/** Raw JSON text of the receipt carried by an artifact (pass it to the kernel as text), or null. */
export function extractReceiptText(a: A2AArtifact): string | null {
  const r = a.metadata?.[FRACTALAI_A2A_EXTENSION];
  if (r === undefined || r === null || !(a.extensions ?? []).includes(FRACTALAI_A2A_EXTENSION)) return null;
  return JSON.stringify(r);
}

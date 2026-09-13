import { readFile } from 'node:fs/promises'

export const PROTOCOL_VERSION = 'w-tvc/1'
export const COMMITMENT_KIND = 30200

export type ParameterCommitment = {
  protocol: string
  kind: number
  address: string
  model_id: string
  version: string
  scheme: string
  vk_digest: string
  transcript_digest: string
  burn_digest: string
  signer: string
  signature: string
}

const HEX_32 = /^[0-9a-f]{64}$/
const HEX_64 = /^[0-9a-f]{128}$/

export class CommitmentError extends Error {}

function requireString(source: Record<string, unknown>, field: string): string {
  const value = source[field]
  if (typeof value !== 'string' || value.length === 0) {
    throw new CommitmentError(`commitment field "${field}" is missing or not a string`)
  }
  return value
}

function requireHex(source: Record<string, unknown>, field: string, pattern: RegExp): string {
  const value = requireString(source, field)
  if (!pattern.test(value)) {
    throw new CommitmentError(
      `commitment field "${field}" must be lowercase hex of the expected width, got "${value}"`,
    )
  }
  return value
}

export function parseCommitment(raw: unknown): ParameterCommitment {
  if (typeof raw !== 'object' || raw === null) {
    throw new CommitmentError('commitment payload is not a JSON object')
  }
  const source = raw as Record<string, unknown>

  const protocol = requireString(source, 'protocol')
  if (protocol !== PROTOCOL_VERSION) {
    throw new CommitmentError(`unsupported protocol "${protocol}", expected "${PROTOCOL_VERSION}"`)
  }

  const kind = source['kind']
  if (kind !== COMMITMENT_KIND) {
    throw new CommitmentError(`unsupported kind ${String(kind)}, expected ${COMMITMENT_KIND}`)
  }

  const commitment: ParameterCommitment = {
    protocol,
    kind: COMMITMENT_KIND,
    address: requireString(source, 'address'),
    model_id: requireString(source, 'model_id'),
    version: requireString(source, 'version'),
    scheme: requireString(source, 'scheme'),
    vk_digest: requireHex(source, 'vk_digest', HEX_32),
    transcript_digest: requireHex(source, 'transcript_digest', HEX_32),
    burn_digest: requireHex(source, 'burn_digest', HEX_32),
    signer: requireHex(source, 'signer', HEX_32),
    signature: requireHex(source, 'signature', HEX_64),
  }

  const derived = `${commitment.model_id}:${commitment.version}`
  if (commitment.address !== derived) {
    throw new CommitmentError(
      `address "${commitment.address}" does not match model and version "${derived}"`,
    )
  }

  return commitment
}

export async function loadCommitment(path: string): Promise<ParameterCommitment> {
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (cause) {
    throw new CommitmentError(`cannot read commitment at ${path}: ${String(cause)}`)
  }
  try {
    return parseCommitment(JSON.parse(text))
  } catch (cause) {
    if (cause instanceof CommitmentError) throw cause
    throw new CommitmentError(`commitment at ${path} is not valid JSON: ${String(cause)}`)
  }
}

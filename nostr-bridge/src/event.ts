import { finalizeEvent, verifyEvent } from 'nostr-tools/pure'
import type { Event, EventTemplate } from 'nostr-tools/pure'

import { COMMITMENT_KIND, PROTOCOL_VERSION, type ParameterCommitment } from './commitment.ts'

export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.primal.net',
  'wss://nostr.mom',
]

export function buildEventTemplate(
  commitment: ParameterCommitment,
  createdAt: number = Math.floor(Date.now() / 1000),
): EventTemplate {
  return {
    kind: COMMITMENT_KIND,
    created_at: createdAt,
    tags: [
      ['d', commitment.address],
      ['vk', commitment.vk_digest],
      ['model', commitment.model_id],
      ['ver', commitment.version],
      ['alg', commitment.scheme],
      ['transcript', commitment.transcript_digest],
      ['burn', commitment.burn_digest],
      ['signer', commitment.signer],
      ['bip340', commitment.signature],
      ['protocol', PROTOCOL_VERSION],
      ['t', 'w-tvc'],
    ],
    content: JSON.stringify(commitment),
  }
}

export function signEvent(
  commitment: ParameterCommitment,
  secretKey: Uint8Array,
  createdAt?: number,
): Event {
  const template =
    createdAt === undefined
      ? buildEventTemplate(commitment)
      : buildEventTemplate(commitment, createdAt)
  const event = finalizeEvent(template, secretKey)
  if (!verifyEvent(event)) {
    throw new Error('finalizeEvent produced an event that failed verification')
  }
  return event
}

export function coordinatesFor(commitment: ParameterCommitment, pubkey: string): string {
  return `${COMMITMENT_KIND}:${pubkey}:${commitment.address}`
}

export function tagValue(event: Pick<Event, 'tags'>, name: string): string | undefined {
  for (const tag of event.tags) {
    if (tag[0] === name) return tag[1]
  }
  return undefined
}

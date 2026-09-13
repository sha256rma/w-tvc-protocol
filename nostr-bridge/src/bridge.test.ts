import assert from 'node:assert/strict'
import { test } from 'node:test'
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'

import { COMMITMENT_KIND, CommitmentError, parseCommitment } from './commitment.ts'
import { buildEventTemplate, coordinatesFor, signEvent, tagValue } from './event.ts'

const VALID = {
  protocol: 'w-tvc/1',
  kind: 30200,
  address: 'acme-llm-7b:2026.09',
  model_id: 'acme-llm-7b',
  version: '2026.09',
  scheme: 'groth16-bn254',
  vk_digest: 'a'.repeat(64),
  transcript_digest: 'b'.repeat(64),
  burn_digest: 'c'.repeat(64),
  signer: 'd'.repeat(64),
  signature: 'e'.repeat(128),
}

test('accepts a well formed commitment', () => {
  const parsed = parseCommitment(VALID)
  assert.equal(parsed.model_id, 'acme-llm-7b')
  assert.equal(parsed.kind, COMMITMENT_KIND)
})

test('rejects an unknown protocol version', () => {
  assert.throws(() => parseCommitment({ ...VALID, protocol: 'w-tvc/2' }), CommitmentError)
})

test('rejects an unknown event kind', () => {
  assert.throws(() => parseCommitment({ ...VALID, kind: 1 }), CommitmentError)
})

test('rejects uppercase and short digests', () => {
  assert.throws(() => parseCommitment({ ...VALID, vk_digest: 'A'.repeat(64) }), CommitmentError)
  assert.throws(() => parseCommitment({ ...VALID, vk_digest: 'a'.repeat(63) }), CommitmentError)
})

test('rejects an address that disagrees with model and version', () => {
  assert.throws(() => parseCommitment({ ...VALID, address: 'other:2026.09' }), CommitmentError)
})

test('event carries the digest in both a tag and its content', () => {
  const template = buildEventTemplate(parseCommitment(VALID), 1789000000)
  assert.equal(template.kind, COMMITMENT_KIND)
  assert.equal(tagValue(template, 'vk'), VALID.vk_digest)
  assert.equal(tagValue(template, 'd'), VALID.address)
  assert.equal(JSON.parse(template.content).vk_digest, VALID.vk_digest)
})

test('signed event verifies and is addressable', () => {
  const secretKey = generateSecretKey()
  const commitment = parseCommitment(VALID)
  const event = signEvent(commitment, secretKey, 1789000000)

  assert.ok(verifyEvent(event))
  assert.equal(event.pubkey, getPublicKey(secretKey))
  assert.equal(event.created_at, 1789000000)
  assert.equal(
    coordinatesFor(commitment, event.pubkey),
    `${COMMITMENT_KIND}:${event.pubkey}:${VALID.address}`,
  )
})

test('pinned created_at makes the event id reproducible', () => {
  const secretKey = generateSecretKey()
  const commitment = parseCommitment(VALID)
  const first = signEvent(commitment, secretKey, 1789000000)
  const second = signEvent(commitment, secretKey, 1789000000)
  assert.equal(first.id, second.id)
})

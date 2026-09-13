import { parseArgs } from 'node:util'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { npubEncode, naddrEncode, nsecEncode } from 'nostr-tools/nip19'
import { SimplePool } from 'nostr-tools/pool'

import { COMMITMENT_KIND, loadCommitment, type ParameterCommitment } from './commitment.ts'
import { DEFAULT_RELAYS, coordinatesFor, signEvent } from './event.ts'

const SECRET_KEY_VAR = 'TVC_SECRET_KEY'

type KeySource = 'environment' | 'generated'

type ResolvedKey = {
  secretKey: Uint8Array
  publicKey: string
  source: KeySource
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`${SECRET_KEY_VAR} must be 64 lowercase hex characters`)
  }
  const bytes = new Uint8Array(32)
  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function resolveKey(): ResolvedKey {
  const fromEnvironment = process.env[SECRET_KEY_VAR]
  if (fromEnvironment && fromEnvironment.trim().length > 0) {
    const secretKey = hexToBytes(fromEnvironment.trim())
    return { secretKey, publicKey: getPublicKey(secretKey), source: 'environment' }
  }
  const secretKey = generateSecretKey()
  return { secretKey, publicKey: getPublicKey(secretKey), source: 'generated' }
}

function reportKeyBinding(commitment: ParameterCommitment, key: ResolvedKey): boolean {
  const bound = key.publicKey === commitment.signer
  console.log('Publishing identity')
  console.log(`  source     ${key.source === 'environment' ? `${SECRET_KEY_VAR}` : 'freshly generated (ephemeral)'}`)
  console.log(`  pubkey     ${key.publicKey}`)
  console.log(`  npub       ${npubEncode(key.publicKey)}`)

  if (bound) {
    console.log('  binding    matches the BIP-340 signer inside the commitment')
    return true
  }

  console.log(`  binding    DOES NOT match the commitment signer ${commitment.signer}`)
  console.log('')
  console.log('  The commitment carries its own BIP-340 signature made by the ceremony key.')
  console.log('  Publishing it from a different Nostr identity still produces a valid event,')
  console.log('  but a wallet pinning the ceremony key will ignore it. For a real broadcast,')
  console.log(`  export ${SECRET_KEY_VAR} to the same key used by "tvc commit".`)
  if (key.source === 'generated') {
    console.log(`  Ephemeral nsec (demo only): ${nsecEncode(key.secretKey)}`)
  }
  return false
}

function describeEvent(event: Event, commitment: ParameterCommitment): void {
  console.log('')
  console.log(`Kind ${COMMITMENT_KIND} parameter commitment event`)
  console.log(`  id         ${event.id}`)
  console.log(`  pubkey     ${event.pubkey}`)
  console.log(`  created_at ${event.created_at}`)
  console.log(`  d tag      ${commitment.address}`)
  console.log(`  vk digest  ${commitment.vk_digest}`)
  console.log(`  coordinate ${coordinatesFor(commitment, event.pubkey)}`)
  console.log(`  naddr      ${naddrEncode({ identifier: commitment.address, pubkey: event.pubkey, kind: COMMITMENT_KIND })}`)
}

async function publishLive(event: Event, relays: string[]): Promise<number> {
  const pool = new SimplePool()
  let accepted = 0
  try {
    const results = await Promise.allSettled(pool.publish(relays, event))
    results.forEach((result, index) => {
      const relay = relays[index] ?? 'unknown relay'
      if (result.status === 'fulfilled') {
        accepted += 1
        console.log(`  accepted  ${relay}`)
      } else {
        console.log(`  refused   ${relay} — ${String(result.reason)}`)
      }
    })
  } finally {
    pool.close(relays)
  }
  return accepted
}

function publishDryRun(event: Event, relays: string[]): void {
  for (const relay of relays) {
    console.log(`  would send  ${relay}`)
  }
  console.log('')
  console.log('  Wire payload:')
  console.log(`  ${JSON.stringify(['EVENT', event])}`)
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      commitment: { type: 'string', short: 'c' },
      relay: { type: 'string', multiple: true, short: 'r' },
      live: { type: 'boolean', default: false },
      'created-at': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  })

  if (values.help || !values.commitment) {
    console.log('Usage: npm run broadcast -- --commitment <path/to/commitment.json> [options]')
    console.log('')
    console.log('Options:')
    console.log('  -c, --commitment <path>  Commitment payload emitted by "tvc commit". Required.')
    console.log('  -r, --relay <url>        Relay to target; repeatable. Defaults to four public relays.')
    console.log('      --created-at <unix>  Pin created_at for a reproducible event id.')
    console.log('      --live               Actually publish. Omitted, the script only simulates.')
    console.log('  -h, --help               Show this message.')
    console.log('')
    console.log(`Signing key is read from ${SECRET_KEY_VAR}; without it an ephemeral key is generated.`)
    return values.help ? 0 : 1
  }

  const commitment = await loadCommitment(values.commitment)
  const relays = values.relay && values.relay.length > 0 ? values.relay : DEFAULT_RELAYS

  console.log('W-TVC parameter commitment broadcast')
  console.log(`  model      ${commitment.model_id} ${commitment.version}`)
  console.log(`  scheme     ${commitment.scheme}`)
  console.log('')

  const key = resolveKey()
  const bound = reportKeyBinding(commitment, key)

  const createdAt = values['created-at'] ? Number.parseInt(values['created-at'], 10) : undefined
  if (createdAt !== undefined && !Number.isFinite(createdAt)) {
    throw new Error('--created-at must be a Unix timestamp in seconds')
  }

  const event = signEvent(commitment, key.secretKey, createdAt)

  describeEvent(event, commitment)

  console.log('')
  if (values.live) {
    if (!bound) {
      console.log('Refusing to publish live from a key that does not match the commitment signer.')
      console.log(`Set ${SECRET_KEY_VAR} to the ceremony key, or drop --live to simulate.`)
      return 1
    }
    console.log(`Publishing to ${relays.length} relays`)
    const accepted = await publishLive(event, relays)
    console.log('')
    console.log(`  ${accepted}/${relays.length} relays accepted the commitment`)
    return accepted > 0 ? 0 : 1
  }

  console.log(`Simulating publication to ${relays.length} relays (no network traffic)`)
  publishDryRun(event, relays)
  console.log('')
  console.log('  Dry run only. Re-run with --live to publish for real.')
  return 0
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((error: unknown) => {
    console.error(`error: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })

import { parseArgs } from 'node:util'
import { verifyEvent } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/pure'
import { SimplePool } from 'nostr-tools/pool'

import { COMMITMENT_KIND, parseCommitment, type ParameterCommitment } from './commitment.ts'
import { DEFAULT_RELAYS, tagValue } from './event.ts'

type Resolution = {
  event: Event
  commitment: ParameterCommitment
}

function reconcile(event: Event): Resolution {
  if (!verifyEvent(event)) {
    throw new Error(`event ${event.id} carries an invalid Nostr signature`)
  }

  const commitment = parseCommitment(JSON.parse(event.content))

  const mismatches: string[] = []
  const expectations: Array<[string, string]> = [
    ['d', commitment.address],
    ['vk', commitment.vk_digest],
    ['model', commitment.model_id],
    ['ver', commitment.version],
    ['alg', commitment.scheme],
    ['transcript', commitment.transcript_digest],
    ['burn', commitment.burn_digest],
    ['signer', commitment.signer],
    ['bip340', commitment.signature],
  ]
  for (const [name, expected] of expectations) {
    const actual = tagValue(event, name)
    if (actual !== expected) {
      mismatches.push(`  tag "${name}": tag says ${String(actual)}, content says ${expected}`)
    }
  }
  if (mismatches.length > 0) {
    throw new Error(`event ${event.id} has tags disagreeing with its content:\n${mismatches.join('\n')}`)
  }

  return { event, commitment }
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      address: { type: 'string', short: 'a' },
      author: { type: 'string' },
      relay: { type: 'string', multiple: true, short: 'r' },
      timeout: { type: 'string', default: '8000' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
    allowPositionals: false,
  })

  if (values.help || !values.address) {
    console.log('Usage: npm run fetch -- --address <model_id:version> [options]')
    console.log('')
    console.log('Options:')
    console.log('  -a, --address <id:ver>  Model address to resolve. Required.')
    console.log('      --author <hex>      Pin the consortium pubkey. Strongly recommended.')
    console.log('  -r, --relay <url>       Relay to query; repeatable.')
    console.log('      --timeout <ms>      Query timeout, default 8000.')
    console.log('  -h, --help              Show this message.')
    console.log('')
    console.log('Without --author this resolves whatever any relay serves, which is not a')
    console.log('trust anchor. A wallet must pin the key whose commitments it honours.')
    return values.help ? 0 : 1
  }

  const relays = values.relay && values.relay.length > 0 ? values.relay : DEFAULT_RELAYS
  const timeout = Number.parseInt(values.timeout ?? '8000', 10)
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error('--timeout must be a positive number of milliseconds')
  }

  const filter: { kinds: number[]; '#d': string[]; authors?: string[] } = {
    kinds: [COMMITMENT_KIND],
    '#d': [values.address],
  }
  if (values.author) {
    filter.authors = [values.author]
  }

  console.log('Resolving W-TVC parameter commitment')
  console.log(`  address  ${values.address}`)
  console.log(`  author   ${values.author ?? 'ANY (not a trust anchor)'}`)
  console.log(`  relays   ${relays.join(', ')}`)
  console.log('')

  const pool = new SimplePool()
  let events: Event[]
  try {
    events = await pool.querySync(relays, filter, { maxWait: timeout })
  } finally {
    pool.close(relays)
  }

  if (events.length === 0) {
    console.log('No commitment found. The model version may not have completed its ceremony,')
    console.log('or none of the queried relays carry it.')
    return 1
  }

  events.sort((left, right) => right.created_at - left.created_at)
  const newest = events[0]
  if (!newest) {
    return 1
  }

  const { commitment } = reconcile(newest)

  console.log(`Found ${events.length} event(s); using the most recent.`)
  console.log('')
  console.log('Verified commitment')
  console.log(`  model       ${commitment.model_id} ${commitment.version}`)
  console.log(`  scheme      ${commitment.scheme}`)
  console.log(`  vk digest   ${commitment.vk_digest}`)
  console.log(`  transcript  ${commitment.transcript_digest}`)
  console.log(`  burn        ${commitment.burn_digest}`)
  console.log(`  signer      ${commitment.signer}`)
  console.log(`  published   ${new Date(newest.created_at * 1000).toISOString()}`)
  console.log('')
  console.log('Verify an inference proof against this digest with:')
  console.log(`  tvc verify --setup <dir> --digest ${commitment.vk_digest}`)

  if (events.length > 1) {
    const distinct = new Set(events.map((event) => tagValue(event, 'vk')))
    if (distinct.size > 1) {
      console.log('')
      console.log(`WARNING: relays served ${distinct.size} different digests for this address.`)
      console.log('Kind 30200 is addressable, so a later event replaces an earlier one at the')
      console.log('same coordinate. Divergence here means either a legitimate re-ceremony or an')
      console.log('attempted silent swap. Pin the digest out of band before trusting it.')
    }
  }

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

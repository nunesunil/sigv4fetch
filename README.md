# sigv4fetch

[![npm version](https://img.shields.io/npm/v/sigv4fetch.svg)](https://www.npmjs.com/package/sigv4fetch)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/nunesunil/sigv4fetch/blob/main/LICENSE)

A compact AWS Signature Version 4 (SigV4) client for [`fetch`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). Sign requests and call AWS REST APIs without the full AWS SDK.

Inspired by [aws4fetch](https://github.com/mhart/aws4fetch), with TypeScript types, injectable Web APIs, and Node.js 22+ as the baseline runtime.

## Requirements

- **Node.js 22+** — native `fetch`, `Request`, `Headers`, `TextEncoder`, and Web Crypto (`crypto.subtle`) are used directly
- **Zero runtime dependencies**

## Install

```bash
pnpm add sigv4fetch
```

```bash
npm install sigv4fetch
```

## Quick start

```typescript
import { AwsClient } from 'sigv4fetch'

const aws = new AwsClient({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
  sessionToken: process.env.AWS_SESSION_TOKEN, // optional, for temporary credentials
})

const response = await aws.fetch('https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-fn/invocations', {
  method: 'POST',
  body: JSON.stringify({ key: 'value' }),
  headers: { 'Content-Type': 'application/json' },
})

console.log(await response.json())
```

Service and region are inferred from the URL when omitted. You can also set defaults on the client:

```typescript
const aws = new AwsClient({
  accessKeyId: '...',
  secretAccessKey: '...',
  service: 's3',
  region: 'us-west-2',
})
```

## API

### `AwsClient`

High-level client for signing and sending requests.

```typescript
import { AwsClient } from 'sigv4fetch'

const aws = new AwsClient({
  accessKeyId: string       // required
  secretAccessKey: string   // required
  sessionToken?: string    // STS / IAM role credentials
  service?: string          // default service (otherwise parsed from URL)
  region?: string           // default region (otherwise parsed from URL)
  cache?: Map<string, ArrayBuffer>  // signing key cache
  retries?: number          // default 10 (0 = no retries)
  initRetryMs?: number      // default 50, doubles each retry with jitter
  api?: AwsApiInput         // optional injected Web APIs (see below)
})
```

#### `aws.sign(input, init?)`

Returns a signed [`Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request). Accepts a URL string or `Request`.

```typescript
const signed = await aws.sign('https://dynamodb.us-east-1.amazonaws.com/', {
  method: 'POST',
  body: JSON.stringify({ TableName: 'MyTable' }),
  headers: {
    'Content-Type': 'application/x-amz-json-1.0',
    'X-Amz-Target': 'DynamoDB_20120810.ListTables',
  },
})

// use with any fetch implementation
await fetch(signed)
```

#### `aws.fetch(input, init?)`

Signs the request and calls `fetch`. Retries on `5xx` and `429` with exponential backoff and jitter.

### `AwsV4Signer`

Lower-level signer when you only need the signed method, URL, headers, and body.

```typescript
import { AwsV4Signer } from 'sigv4fetch'

const signer = new AwsV4Signer({
  url: 'https://example-bucket.s3.amazonaws.com/object.txt',
  accessKeyId: '...',
  secretAccessKey: '...',
  method: 'GET',
})

const { method, url, headers, body } = await signer.sign()
```

## Per-request options

Pass signing overrides via `init.aws`:

```typescript
await aws.fetch(url, {
  method: 'PUT',
  body: fileContents,
  headers: { 'Content-Type': 'text/plain' },
  aws: {
    service: 's3',
    region: 'eu-west-1',
    datetime: '20150830T123600Z', // fixed timestamp (testing / replay)
  },
})
```

| Option | Description |
| --- | --- |
| `accessKeyId` | Override client access key |
| `secretAccessKey` | Override client secret key |
| `sessionToken` | Temporary credential token |
| `service` | AWS service name |
| `region` | AWS region |
| `datetime` | SigV4 timestamp (`YYYYMMDDTHHmmssZ`) |
| `signQuery` | Sign query string instead of `Authorization` header (presigned URLs) |
| `appendSessionToken` | Append `X-Amz-Security-Token` after signing (default for IoT gateway) |
| `allHeaders` | Sign all headers instead of the default subset |
| `singleEncode` | Only encode `%2F` once (mainly for testing) |
| `cache` | Per-request signing key cache |

## Presigned URLs

```typescript
const signer = new AwsV4Signer({
  url: 'https://my-bucket.s3.amazonaws.com/report.pdf',
  accessKeyId: '...',
  secretAccessKey: '...',
  signQuery: true,
})

const { url } = await signer.sign()
console.log(url.toString()) // shareable presigned URL
```

S3 presigned URLs default to `X-Amz-Expires=86400` (24 hours) when not set.

## Injectable Web APIs

Optionally inject `fetch`, `Request`, `Headers`, `crypto`, and `TextEncoder`. Useful for tests or custom `fetch` implementations:

```typescript
import { AwsClient, getDefaultApi } from 'sigv4fetch'

const api = getDefaultApi()

const aws = new AwsClient({
  accessKeyId: '...',
  secretAccessKey: '...',
  api: {
    ...api,
    fetch: myCustomFetch,
  },
})
```

On Node 22+, globals are available out of the box — injection is optional.

**Note:** When injecting `Request`, pass `Request` instances created from the same constructor (`input instanceof aws.api.Request`).

## Supported environments

| Environment | Support |
| --- | --- |
| Node.js 22+ | ✅ Native globals |
| Cloudflare Workers | ✅ (Web Crypto + fetch) |
| Browsers | ✅ |
| Deno / Bun | ✅ (with fetch + Web Crypto) |

## Body types

Request bodies must be a **string**, **ArrayBuffer**, or **ArrayBufferView** unless you set the `X-Amz-Content-Sha256` header yourself. `Blob`, `FormData`, and readable streams are not hashed automatically.

S3 requests use `UNSIGNED-PAYLOAD` by default for the payload hash unless you provide `X-Amz-Content-Sha256`.

## Development

```bash
pnpm install
pnpm run typecheck
pnpm run build
pnpm run dev      # watch mode
```

## Publish

```bash
pnpm run prepublishOnly   # typecheck + build
npm publish
```

## License

MIT © [nunesunil](https://github.com/nunesunil)

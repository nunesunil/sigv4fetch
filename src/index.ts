import { XMLParser } from "fast-xml-parser";

export interface AwsApi {
	fetch: typeof fetch;
	Request: typeof Request;
	Headers: typeof Headers;
	crypto: Crypto;
	TextEncoder: typeof TextEncoder;
}

export type AwsApiInput = Partial<AwsApi>;

function getDefaultApi(): AwsApi {
	const { fetch, Request, Headers, crypto, TextEncoder } = globalThis;
	if (
		fetch == null ||
		Request == null ||
		Headers == null ||
		crypto == null ||
		TextEncoder == null
	) {
		throw new TypeError(
			"Missing required Web APIs. Pass an `api` option with fetch, Request, Headers, crypto, and TextEncoder.",
		);
	}
	return {
		fetch: fetch.bind(globalThis),
		Request,
		Headers,
		crypto,
		TextEncoder,
	};
}

/** Default Web API implementations from `globalThis` (resolved lazily on access). */
export const DEFAULT_API: AwsApi = new Proxy({} as AwsApi, {
	get(_target, prop: keyof AwsApi) {
		return getDefaultApi()[prop];
	},
});

function resolveApi(api?: AwsApiInput): AwsApi {
	if (api == null) {
		return getDefaultApi();
	}
	const defaults = getDefaultApi();
	return {
		fetch: api.fetch ?? defaults.fetch,
		Request: api.Request ?? defaults.Request,
		Headers: api.Headers ?? defaults.Headers,
		crypto: api.crypto ?? defaults.crypto,
		TextEncoder: api.TextEncoder ?? defaults.TextEncoder,
	};
}

export { getDefaultApi };

export interface AwsSigningOptions {
	accessKeyId?: string;
	secretAccessKey?: string;
	sessionToken?: string;
	service?: string;
	region?: string;
	cache?: Map<string, ArrayBuffer>;
	datetime?: string;
	signQuery?: boolean;
	appendSessionToken?: boolean;
	allHeaders?: boolean;
	singleEncode?: boolean;
}

export type AwsRequestOptions = AwsSigningOptions;

export interface AwsClientOptions extends AwsSigningOptions {
	accessKeyId: string;
	secretAccessKey: string;
	retries?: number;
	initRetryMs?: number;
	api?: AwsApiInput;
}

export type AwsRequestInit = RequestInit & {
	aws?: AwsSigningOptions;
};

export interface AwsV4SignerOptions extends AwsSigningOptions {
	method?: string;
	url: string;
	headers?: HeadersInit;
	body?: BodyInit | null;
	accessKeyId: string;
	secretAccessKey: string;
	api?: AwsApiInput;
	textEncoder?: TextEncoder;
}

export interface SignedRequest {
	method: string;
	url: URL;
	headers: Headers;
	body?: BodyInit | null;
}

export type SignedAwsRequest = SignedRequest;

type SignInput = Request | { toString(): string };

export interface S3Client {
	buildBucketUrl: (bucketName: string) => string;
	s3: AwsClient;
}

export interface CustomS3ClientOptions {
	/** Do not include `https://` or `http://`. */
	host: string;
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
	region?: string;
	forcePathStyle?: boolean;
	secure?: boolean;
	api?: AwsApiInput;
}

export interface CloudflareR2ClientOptions {
	accountId: string;
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
	jurisdiction?: "eu" | "fedramp";
	api?: AwsApiInput;
}

export type ListObjectsV2SortBy =
	| "key"
	| "lastModified"
	| "size"
	| "eTag"
	| "storageClass";

export interface ListObjectsV2Options {
	bucket: string;
	continuationToken?: string;
	delimiter?: string;
	encodingType?: string;
	fetchOwner?: boolean;
	maxKeys?: number;
	prefix?: string;
	startAfter?: string;
	sortBy?: ListObjectsV2SortBy;
	sortDirection?: "asc" | "desc";
}

export interface S3ObjectOwner {
	displayName: string;
	id: string;
}

export interface S3ObjectRestoreStatus {
	isRestoreInProgress: boolean;
	restoreExpiration?: Date;
}

export interface S3Object {
	checksumAlgorithm?: string;
	checksumType?: string;
	eTag: string;
	key: string;
	lastModified: Date;
	owner?: S3ObjectOwner;
	restoreStatus?: S3ObjectRestoreStatus;
	size: number;
	storageClass: string;
}

export interface ListObjectsV2Result {
	commonPrefixes: Array<{ prefix: string }>;
	contents: S3Object[];
	continuationToken?: string;
	delimiter?: string;
	encodingType?: string;
	isTruncated: boolean;
	keyCount: number;
	maxKeys: number;
	name: string;
	nextContinuationToken?: string;
	prefix?: string;
	startAfter?: string;
}

export type ObjectMetadata = Record<string, string>;
export type Tagging = Record<string, string>;

export interface HeadObjectOptions {
	bucket: string;
	key: string;
	versionId?: string;
}

export interface HeadObjectResult {
	contentType: string;
	contentLength: number;
	eTag: string;
	metadata: ObjectMetadata;
	taggingCount: number;
}

export interface GetObjectOptions extends HeadObjectOptions {
	range?: string;
}

export interface GetObjectBlobResult extends HeadObjectResult {
	blob: Blob;
}

export interface PutObjectOptions {
	bucket: string;
	key: string;
	body: BodyInit;
	contentType: string;
	contentLength?: number;
	metadata?: ObjectMetadata;
	acl?: string;
	storageClass?: string;
	cacheControl?: string;
	tagging?: Tagging;
}

export interface PutObjectResult {
	eTag: string;
	versionId?: string;
}

export interface DeleteObjectOptions {
	bucket: string;
	key: string;
	versionId?: string;
}

export interface DeleteObjectsOptions {
	bucket: string;
	objects: Array<{
		key: string;
		versionId?: string;
		eTag?: string;
	}>;
	quiet?: boolean;
}

export interface DeleteObjectsResult {
	deleted: Array<{
		deleteMarker?: boolean;
		deleteMarkerVersionId?: string;
		key: string;
		versionId?: string;
	}>;
	errors: Array<{
		code: string;
		message: string;
		key: string;
		versionId?: string;
	}>;
}

const HOST_SERVICES: Record<string, string> = {
	appstream2: "appstream",
	cloudhsmv2: "cloudhsm",
	email: "ses",
	marketplace: "aws-marketplace",
	mobile: "AWSMobileHubService",
	pinpoint: "mobiletargeting",
	queue: "sqs",
	"git-codecommit": "codecommit",
	"mturk-requester-sandbox": "mturk-requester",
	"personalize-runtime": "personalize",
};

// https://github.com/aws/aws-sdk-js/blob/cc29728c1c4178969ebabe3bbe6b6f3159436394/lib/signers/v4.js#L190-L198
const UNSIGNABLE_HEADERS = new Set([
	"authorization",
	"content-type",
	"content-length",
	"user-agent",
	"presigned-expires",
	"expect",
	"x-amzn-trace-id",
	"range",
	"connection",
]);

function mergeSigningOptions(
	client: AwsClient,
	init?: AwsRequestInit,
): Omit<AwsV4SignerOptions, "url"> {
	const aws = init?.aws;
	return {
		method: init?.method,
		headers: init?.headers,
		body: init?.body,
		accessKeyId: aws?.accessKeyId ?? client.accessKeyId,
		secretAccessKey: aws?.secretAccessKey ?? client.secretAccessKey,
		sessionToken: aws?.sessionToken ?? client.sessionToken,
		service: aws?.service ?? client.service,
		region: aws?.region ?? client.region,
		cache: aws?.cache ?? client.cache,
		datetime: aws?.datetime,
		signQuery: aws?.signQuery,
		appendSessionToken: aws?.appendSessionToken,
		allHeaders: aws?.allHeaders,
		singleEncode: aws?.singleEncode,
		api: client.api,
		textEncoder: client.textEncoder,
	};
}

async function normalizeRequestInput(
	input: Request,
	init?: AwsRequestInit,
): Promise<{ input: string; init: AwsRequestInit | undefined }> {
	const { method, headers, body } = input;
	const mergedInit: AwsRequestInit = { ...init, method, headers };
	if (mergedInit.body == null && body != null) {
		mergedInit.body = await input.clone().arrayBuffer();
	}
	return { input: input.url, init: mergedInit };
}

function toRequestInit(
	init: AwsRequestInit | undefined,
	signed: SignedRequest,
): RequestInit {
	const { aws: _aws, ...requestInit } = init ?? {};
	return {
		...requestInit,
		method: signed.method,
		headers: signed.headers,
		body: signed.body,
	};
}

export function customS3Client({
	host,
	accessKeyId,
	secretAccessKey,
	sessionToken,
	forcePathStyle = false,
	region = "us-east-1",
	secure = true,
	api,
}: CustomS3ClientOptions): S3Client {
	return {
		buildBucketUrl: (bucketName) =>
			`http${secure ? "s" : ""}://${
				forcePathStyle ? `${host}/${bucketName}` : `${bucketName}.${host}`
			}`,
		s3: new AwsClient({
			accessKeyId,
			secretAccessKey,
			sessionToken,
			region,
			service: "s3",
			retries: 0,
			api,
		}),
	};
}

export function cloudflareR2Client({
	accountId,
	accessKeyId,
	secretAccessKey,
	sessionToken,
	jurisdiction,
	api,
}: CloudflareR2ClientOptions): S3Client {
	const host = `${accountId}.${jurisdiction ? `${jurisdiction}.` : ""}r2.cloudflarestorage.com`;

	return customS3Client({
		host,
		accessKeyId,
		secretAccessKey,
		sessionToken,
		region: "auto",
		api,
	});
}

export async function listObjectsV2(
	client: S3Client,
	options: ListObjectsV2Options,
): Promise<ListObjectsV2Result> {
	const url = new URL(client.buildBucketUrl(options.bucket));
	url.searchParams.set("list-type", "2");

	if (options.continuationToken) {
		url.searchParams.set("continuation-token", options.continuationToken);
	}
	if (options.delimiter) {
		url.searchParams.set("delimiter", options.delimiter);
	}
	if (options.encodingType) {
		url.searchParams.set("encoding-type", options.encodingType);
	}
	if (options.fetchOwner) {
		url.searchParams.set("fetch-owner", "true");
	}
	if (options.maxKeys != null) {
		url.searchParams.set("max-keys", options.maxKeys.toString());
	}
	if (options.prefix) {
		url.searchParams.set("prefix", options.prefix);
	}
	if (options.startAfter) {
		url.searchParams.set("start-after", options.startAfter);
	}

	const res = await client.s3.fetch(url.toString(), {
		method: "GET",
		aws: { signQuery: true, allHeaders: true },
	});
	await throwS3Error(res);

	const parsed = parseS3Xml<ListObjectsV2Xml>(await res.text(), {
		arrayPath: ["ListBucketResult.CommonPrefixes", "ListBucketResult.Contents"],
	});
	const result = mapListObjectsV2Result(parsed);

	if (options.sortBy) {
		sortS3Objects(result.contents, options.sortBy, options.sortDirection ?? "asc");
	}

	return result;
}

export async function putObject(
	client: S3Client,
	options: PutObjectOptions,
): Promise<PutObjectResult> {
	assertObjectKey(options.key);

	const contentLength =
		options.contentLength ?? getBodyContentLength(options.body);
	const headers: Record<string, string> = {
		"content-type": options.contentType,
		...(contentLength == null
			? {}
			: { "content-length": contentLength.toString() }),
		...(options.acl ? { "x-amz-acl": options.acl } : {}),
		...(options.storageClass
			? { "x-amz-storage-class": options.storageClass }
			: {}),
		...(options.cacheControl ? { "cache-control": options.cacheControl } : {}),
		...(options.tagging ? { "x-amz-tagging": encodeTagging(options.tagging) } : {}),
		...metadataHeaders(options.metadata),
	};

	const res = await throwS3Error(
		await client.s3.fetch(buildObjectUrl(client, options.bucket, options.key), {
			method: "PUT",
			headers,
			body: options.body,
			aws: { signQuery: true, allHeaders: true },
		}),
	);

	return {
		eTag: res.headers.get("etag") ?? "",
		versionId: res.headers.get("x-amz-version-id") ?? undefined,
	};
}

export async function headObject(
	client: S3Client,
	options: HeadObjectOptions,
): Promise<HeadObjectResult> {
	assertObjectKey(options.key);

	const res = await throwS3Error(
		await client.s3.fetch(buildObjectUrl(client, options.bucket, options.key, {
			versionId: options.versionId,
		}), {
			method: "HEAD",
			aws: { signQuery: true, allHeaders: true },
		}),
	);

	return parseHeadObjectHeaders(res.headers);
}

export async function getObjectBlob(
	client: S3Client,
	options: GetObjectOptions,
): Promise<GetObjectBlobResult> {
	assertObjectKey(options.key);

	const res = await throwS3Error(
		await client.s3.fetch(buildObjectUrl(client, options.bucket, options.key, {
			versionId: options.versionId,
		}), {
			method: "GET",
			headers: options.range ? { range: options.range } : undefined,
			aws: { signQuery: true, allHeaders: true },
		}),
	);

	return {
		blob: await res.blob(),
		...parseHeadObjectHeaders(res.headers),
	};
}

export async function deleteObject(
	client: S3Client,
	options: DeleteObjectOptions,
): Promise<void> {
	assertObjectKey(options.key);

	await throwS3Error(
		await client.s3.fetch(buildObjectUrl(client, options.bucket, options.key, {
			versionId: options.versionId,
		}), {
			method: "DELETE",
			aws: { signQuery: true, allHeaders: true },
		}),
	);
}

export async function deleteObjects(
	client: S3Client,
	options: DeleteObjectsOptions,
): Promise<DeleteObjectsResult> {
	if (options.objects.length === 0) {
		throw new Error("No objects provided for deletion.");
	}
	if (options.objects.length > 1000) {
		throw new Error("Cannot delete more than 1000 objects in a single request.");
	}
	for (const object of options.objects) {
		assertObjectKey(object.key);
	}

	const body = buildDeleteObjectsXml(options);
	const res = await throwS3Error(
		await client.s3.fetch(`${client.buildBucketUrl(options.bucket)}/?delete`, {
			method: "POST",
			headers: {
				"content-type": "application/xml",
				"content-length": getBodyContentLength(body)?.toString() ?? "0",
				"content-md5": md5Base64(client.s3.textEncoder, body),
				"x-amz-checksum-sha256": await sha256Base64(
					client.s3.api.crypto,
					client.s3.textEncoder,
					body,
				),
			},
			body,
			aws: { signQuery: true, allHeaders: true },
		}),
	);
	const parsed = parseS3Xml<DeleteObjectsXml>(await res.text(), {
		arrayPath: ["DeleteResult.Deleted", "DeleteResult.Error"],
	});

	return mapDeleteObjectsResult(parsed);
}

export class AwsClient {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
	service?: string;
	region?: string;
	cache: Map<string, ArrayBuffer>;
	retries: number;
	initRetryMs: number;
	api: AwsApi;
	textEncoder: TextEncoder;

	constructor({
		accessKeyId,
		secretAccessKey,
		sessionToken,
		service,
		region,
		cache,
		retries,
		initRetryMs,
		api,
	}: AwsClientOptions) {
		if (accessKeyId == null)
			throw new TypeError("accessKeyId is a required option");
		if (secretAccessKey == null)
			throw new TypeError("secretAccessKey is a required option");
		this.api = resolveApi(api);
		this.textEncoder = new this.api.TextEncoder();
		this.accessKeyId = accessKeyId;
		this.secretAccessKey = secretAccessKey;
		this.sessionToken = sessionToken;
		this.service = service;
		this.region = region;
		this.cache = cache ?? new Map();
		this.retries = retries ?? 10; // Up to 25.6 secs
		this.initRetryMs = initRetryMs ?? 50;
	}

	async sign(input: SignInput, init?: AwsRequestInit): Promise<Request> {
		if (input instanceof this.api.Request) {
			({ input, init } = await normalizeRequestInput(input, init));
		}
		const signer = new AwsV4Signer({
			url: input.toString(),
			...mergeSigningOptions(this, init),
		});
		const signed = await signer.sign();
		const requestInit = toRequestInit(init, signed);
		try {
			return new this.api.Request(signed.url.toString(), requestInit);
		} catch (e) {
			if (e instanceof TypeError) {
				// https://bugs.chromium.org/p/chromium/issues/detail?id=1360943
				return new this.api.Request(signed.url.toString(), {
					...requestInit,
					duplex: "half",
				} as RequestInit);
			}
			throw e;
		}
	}

	async fetch(input: SignInput, init?: AwsRequestInit): Promise<Response> {
		// Normalize Request once so retries do not re-read a consumed body stream.
		if (input instanceof this.api.Request) {
			({ input, init } = await normalizeRequestInput(input, init));
		}
		for (let i = 0; i <= this.retries; i++) {
			const fetched = this.api.fetch(await this.sign(input, init));
			if (i === this.retries) {
				return fetched;
			}
			const res = await fetched;
			if (res.status < 500 && res.status !== 429) {
				return res;
			}
			await new Promise((resolve) =>
				setTimeout(resolve, Math.random() * this.initRetryMs * 2 ** i),
			);
		}
		throw new Error(
			"An unknown error occurred, ensure retries is not negative",
		);
	}
}

export class AwsV4Signer {
	method: string;
	url: URL;
	headers: Headers;
	body?: BodyInit | null;
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
	service: string;
	region: string;
	cache: Map<string, ArrayBuffer>;
	datetime: string;
	signQuery?: boolean;
	appendSessionToken?: boolean;
	signableHeaders: string[];
	signedHeaders: string;
	canonicalHeaders: string;
	credentialString: string;
	encodedPath: string;
	encodedSearch: string;
	api: AwsApi;
	textEncoder: TextEncoder;

	constructor({
		method,
		url,
		headers,
		body,
		accessKeyId,
		secretAccessKey,
		sessionToken,
		service,
		region,
		cache,
		datetime,
		signQuery,
		appendSessionToken,
		allHeaders,
		singleEncode,
		api,
		textEncoder,
	}: AwsV4SignerOptions) {
		if (url == null) throw new TypeError("url is a required option");
		if (accessKeyId == null)
			throw new TypeError("accessKeyId is a required option");
		if (secretAccessKey == null)
			throw new TypeError("secretAccessKey is a required option");

		this.api = resolveApi(api);
		this.textEncoder = textEncoder ?? new this.api.TextEncoder();

		this.method = method ?? (body ? "POST" : "GET");
		this.url = new URL(url);
		this.headers = new this.api.Headers(headers ?? {});
		this.body = body;

		this.accessKeyId = accessKeyId;
		this.secretAccessKey = secretAccessKey;
		this.sessionToken = sessionToken;

		let guessedService: string | undefined;
		let guessedRegion: string | undefined;
		if (!service || !region) {
			[guessedService, guessedRegion] = guessServiceRegion(
				this.url,
				this.headers,
			);
		}
		this.service = service || guessedService || "";
		this.region = region || guessedRegion || "us-east-1";

		this.cache = cache ?? new Map();
		this.datetime =
			datetime ?? new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
		this.signQuery = signQuery;
		this.appendSessionToken =
			appendSessionToken ?? this.service === "iotdevicegateway";

		this.headers.delete("Host"); // Can't be set in insecure env anyway

		if (
			this.service === "s3" &&
			!this.signQuery &&
			!this.headers.has("X-Amz-Content-Sha256")
		) {
			this.headers.set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD");
		}

		const params = this.signQuery ? this.url.searchParams : this.headers;

		params.set("X-Amz-Date", this.datetime);
		if (this.sessionToken && !this.appendSessionToken) {
			params.set("X-Amz-Security-Token", this.sessionToken);
		}

		// headers are always lowercase after normalization
		this.signableHeaders = ["host", ...getHeaderNames(this.headers)]
			.filter((header) => allHeaders || !UNSIGNABLE_HEADERS.has(header))
			.sort();

		this.signedHeaders = this.signableHeaders.join(";");

		// headers are always trimmed:
		// https://fetch.spec.whatwg.org/#concept-header-value-normalize
		this.canonicalHeaders = this.signableHeaders
			.map(
				(header) =>
					header +
					":" +
					(header === "host"
						? this.url.host
						: (this.headers.get(header) || "").replace(/\s+/g, " ")),
			)
			.join("\n");

		this.credentialString = [
			this.datetime.slice(0, 8),
			this.region,
			this.service,
			"aws4_request",
		].join("/");

		if (this.signQuery) {
			if (this.service === "s3" && !params.has("X-Amz-Expires")) {
				params.set("X-Amz-Expires", "86400"); // 24 hours
			}
			params.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
			params.set(
				"X-Amz-Credential",
				`${this.accessKeyId}/${this.credentialString}`,
			);
			params.set("X-Amz-SignedHeaders", this.signedHeaders);
		}

		if (this.service === "s3") {
			try {
				this.encodedPath = decodeURIComponent(
					this.url.pathname.replace(/\+/g, " "),
				);
			} catch {
				this.encodedPath = this.url.pathname;
			}
		} else {
			this.encodedPath = this.url.pathname.replace(/\/+/g, "/");
		}
		if (!singleEncode) {
			this.encodedPath = encodeURIComponent(this.encodedPath).replace(
				/%2F/g,
				"/",
			);
		}
		this.encodedPath = encodeRfc3986(this.encodedPath);

		const seenKeys = new Set<string>();
		this.encodedSearch = getSearchParamPairs(this.url.searchParams)
			.filter(([k]) => {
				if (!k) return false; // no empty keys
				if (this.service === "s3") {
					if (seenKeys.has(k)) return false; // first val only for S3
					seenKeys.add(k);
				}
				return true;
			})
			.map(([key, value]): [string, string] => [
				encodeRfc3986(encodeURIComponent(key)),
				encodeRfc3986(encodeURIComponent(value)),
			])
			.sort(([k1, v1], [k2, v2]) =>
				k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0,
			)
			.map((pair) => pair.join("="))
			.join("&");
	}

	async sign(): Promise<SignedRequest> {
		if (this.signQuery) {
			this.url.searchParams.set("X-Amz-Signature", await this.signature());
			if (this.sessionToken && this.appendSessionToken) {
				this.url.searchParams.set("X-Amz-Security-Token", this.sessionToken);
			}
		} else {
			this.headers.set("Authorization", await this.authHeader());
		}

		return {
			method: this.method,
			url: this.url,
			headers: this.headers,
			body: this.body,
		};
	}

	async authHeader(): Promise<string> {
		return [
			"AWS4-HMAC-SHA256 Credential=" +
				this.accessKeyId +
				"/" +
				this.credentialString,
			`SignedHeaders=${this.signedHeaders}`,
			`Signature=${await this.signature()}`,
		].join(", ");
	}

	async signature(): Promise<string> {
		const date = this.datetime.slice(0, 8);
		const cacheKey = [
			this.secretAccessKey,
			date,
			this.region,
			this.service,
		].join();
		let kCredentials = this.cache.get(cacheKey);
		if (!kCredentials) {
			const kDate = await hmac(
				this.api.crypto,
				this.textEncoder,
				`AWS4${this.secretAccessKey}`,
				date,
			);
			const kRegion = await hmac(
				this.api.crypto,
				this.textEncoder,
				kDate,
				this.region,
			);
			const kService = await hmac(
				this.api.crypto,
				this.textEncoder,
				kRegion,
				this.service,
			);
			kCredentials = await hmac(
				this.api.crypto,
				this.textEncoder,
				kService,
				"aws4_request",
			);
			this.cache.set(cacheKey, kCredentials);
		}
		return buf2hex(
			await hmac(
				this.api.crypto,
				this.textEncoder,
				kCredentials,
				await this.stringToSign(),
			),
		);
	}

	async stringToSign(): Promise<string> {
		return [
			"AWS4-HMAC-SHA256",
			this.datetime,
			this.credentialString,
			buf2hex(
				await hash(
					this.api.crypto,
					this.textEncoder,
					await this.canonicalString(),
				),
			),
		].join("\n");
	}

	async canonicalString(): Promise<string> {
		return [
			this.method.toUpperCase(),
			this.encodedPath,
			this.encodedSearch,
			`${this.canonicalHeaders}\n`,
			this.signedHeaders,
			await this.hexBodyHash(),
		].join("\n");
	}

	async hexBodyHash(): Promise<string> {
		let hashHeader =
			this.headers.get("X-Amz-Content-Sha256") ||
			(this.service === "s3" && this.signQuery ? "UNSIGNED-PAYLOAD" : null);
		if (hashHeader == null) {
			if (this.body && !isHashableBody(this.body)) {
				throw new Error(
					"body must be a string, ArrayBuffer or ArrayBufferView, unless you include the X-Amz-Content-Sha256 header",
				);
			}
			hashHeader = buf2hex(
				await hash(this.api.crypto, this.textEncoder, this.body ?? ""),
			);
		}
		return hashHeader;
	}
}

type ListObjectsV2Xml = {
	ListBucketResult: {
		CommonPrefixes?: Array<{ Prefix?: unknown }>;
		Contents?: Array<{
			ChecksumAlgorithm?: unknown;
			ChecksumType?: unknown;
			ETag?: unknown;
			Key?: unknown;
			LastModified?: unknown;
			Owner?: {
				DisplayName?: unknown;
				ID?: unknown;
			};
			RestoreStatus?: {
				IsRestoreInProgress?: unknown;
				RestoreExpiration?: unknown;
			};
			Size?: unknown;
			StorageClass?: unknown;
		}>;
		ContinuationToken?: unknown;
		Delimiter?: unknown;
		EncodingType?: unknown;
		IsTruncated?: unknown;
		KeyCount?: unknown;
		MaxKeys?: unknown;
		Name?: unknown;
		NextContinuationToken?: unknown;
		Prefix?: unknown;
		StartAfter?: unknown;
	};
};

type S3ErrorXml = {
	Error?: {
		Code?: unknown;
		Message?: unknown;
	};
};

type DeleteObjectsXml = {
	DeleteResult?: {
		Deleted?: Array<{
			DeleteMarker?: unknown;
			DeleteMarkerVersionId?: unknown;
			Key?: unknown;
			VersionId?: unknown;
		}>;
		Error?: Array<{
			Code?: unknown;
			Key?: unknown;
			Message?: unknown;
			VersionId?: unknown;
		}>;
	};
};

function parseS3Xml<T>(
	xml: string,
	options?: {
		arrayPath?: string[];
	},
): T {
	const parser = new XMLParser({
		ignoreAttributes: true,
		parseTagValue: false,
		isArray: (_name, path) =>
			typeof path === "string" && (options?.arrayPath?.includes(path) ?? false),
	});
	return parser.parse(xml) as T;
}

async function throwS3Error(res: Response): Promise<Response> {
	if (res.ok) return res;

	const text = await res.text();
	try {
		const parsed = parseS3Xml<S3ErrorXml>(text);
		const code = toOptionalString(parsed.Error?.Code) ?? res.status.toString();
		const message = toOptionalString(parsed.Error?.Message) ?? res.statusText;
		throw new Error(`${code} - ${message}`);
	} catch (error) {
		if (error instanceof Error && error.message.includes(" - ")) {
			throw error;
		}
		throw new Error(`${res.status} - ${res.statusText}`);
	}
}

function mapListObjectsV2Result(parsed: ListObjectsV2Xml): ListObjectsV2Result {
	const result = parsed.ListBucketResult;

	return {
		commonPrefixes: (result.CommonPrefixes ?? []).map((item) => ({
			prefix: toStringValue(item.Prefix),
		})),
		contents: (result.Contents ?? []).map((item) => ({
			checksumAlgorithm: toOptionalString(item.ChecksumAlgorithm),
			checksumType: toOptionalString(item.ChecksumType),
			eTag: toStringValue(item.ETag),
			key: toStringValue(item.Key),
			lastModified: toDateValue(item.LastModified),
			owner: item.Owner
				? {
						displayName: toStringValue(item.Owner.DisplayName),
						id: toStringValue(item.Owner.ID),
					}
				: undefined,
			restoreStatus: item.RestoreStatus
				? {
						isRestoreInProgress: toBooleanValue(
							item.RestoreStatus.IsRestoreInProgress,
						),
						restoreExpiration: item.RestoreStatus.RestoreExpiration
							? toDateValue(item.RestoreStatus.RestoreExpiration)
							: undefined,
					}
				: undefined,
			size: toNumberValue(item.Size),
			storageClass: toStringValue(item.StorageClass),
		})),
		continuationToken: toOptionalString(result.ContinuationToken),
		delimiter: toOptionalString(result.Delimiter),
		encodingType: toOptionalString(result.EncodingType),
		isTruncated: toBooleanValue(result.IsTruncated),
		keyCount: toNumberValue(result.KeyCount),
		maxKeys: toNumberValue(result.MaxKeys),
		name: toStringValue(result.Name),
		nextContinuationToken: toOptionalString(result.NextContinuationToken),
		prefix: toOptionalString(result.Prefix),
		startAfter: toOptionalString(result.StartAfter),
	};
}

function mapDeleteObjectsResult(parsed: DeleteObjectsXml): DeleteObjectsResult {
	const result = parsed.DeleteResult;

	return {
		deleted: (result?.Deleted ?? []).map((item) => ({
			deleteMarker:
				item.DeleteMarker == null
					? undefined
					: toBooleanValue(item.DeleteMarker),
			deleteMarkerVersionId: toOptionalString(item.DeleteMarkerVersionId),
			key: toStringValue(item.Key),
			versionId: toOptionalString(item.VersionId),
		})),
		errors: (result?.Error ?? []).map((item) => ({
			code: toStringValue(item.Code),
			message: toStringValue(item.Message),
			key: toStringValue(item.Key),
			versionId: toOptionalString(item.VersionId),
		})),
	};
}

function sortS3Objects(
	objects: S3Object[],
	sortBy: ListObjectsV2SortBy,
	direction: "asc" | "desc",
): void {
	const multiplier = direction === "asc" ? 1 : -1;
	objects.sort((a, b) => multiplier * compareS3ObjectField(a, b, sortBy));
}

function compareS3ObjectField(
	a: S3Object,
	b: S3Object,
	sortBy: ListObjectsV2SortBy,
): number {
	if (sortBy === "lastModified") {
		return a.lastModified.getTime() - b.lastModified.getTime();
	}
	if (sortBy === "size") {
		return a.size - b.size;
	}
	return a[sortBy].localeCompare(b[sortBy]);
}

function toOptionalString(value: unknown): string | undefined {
	return value == null ? undefined : String(value);
}

function toStringValue(value: unknown): string {
	return toOptionalString(value) ?? "";
}

function toNumberValue(value: unknown): number {
	return typeof value === "number" ? value : Number(value ?? 0);
}

function toBooleanValue(value: unknown): boolean {
	return value === true || value === "true";
}

function toDateValue(value: unknown): Date {
	return new Date(toStringValue(value));
}

function buildObjectUrl(
	client: S3Client,
	bucket: string,
	key: string,
	params?: {
		versionId?: string;
	},
): string {
	const url = new URL(`${client.buildBucketUrl(bucket)}/${encodeS3Key(key)}`);
	if (params?.versionId) {
		url.searchParams.set("versionId", params.versionId);
	}
	return url.toString();
}

function encodeS3Key(key: string): string {
	return key.split("/").map(encodeURIComponent).join("/");
}

function assertObjectKey(key: string): void {
	if (!key.trim()) {
		throw new Error("The object key cannot be empty.");
	}
}

function parseHeadObjectHeaders(headers: Headers): HeadObjectResult {
	const metadata: ObjectMetadata = {};

	headers.forEach((value, key) => {
		if (key.toLowerCase().startsWith("x-amz-meta-")) {
			metadata[key.slice("x-amz-meta-".length)] = value;
		}
	});

	return {
		contentType: headers.get("content-type") ?? "",
		contentLength: Number(headers.get("content-length") ?? 0),
		eTag: headers.get("etag") ?? "",
		metadata,
		taggingCount: Number(headers.get("x-amz-tagging-count") ?? 0),
	};
}

function getBodyContentLength(body: BodyInit | null): number | null {
	if (body == null) return 0;
	if (typeof body === "string") return new TextEncoder().encode(body).length;
	if (body instanceof Blob) return body.size;
	if (body instanceof ArrayBuffer) return body.byteLength;
	if (ArrayBuffer.isView(body)) return body.byteLength;
	if (body instanceof URLSearchParams) {
		return new TextEncoder().encode(body.toString()).length;
	}
	if (body instanceof FormData) return null;
	if (body instanceof ReadableStream) return null;
	return null;
}

function metadataHeaders(metadata?: ObjectMetadata): Record<string, string> {
	return Object.fromEntries(
		Object.entries(metadata ?? {}).map(([key, value]) => [
			`x-amz-meta-${key.toLowerCase()}`,
			value,
		]),
	);
}

function encodeTagging(tagging: Tagging): string {
	return Object.entries(tagging)
		.map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
		.join("&");
}

function buildDeleteObjectsXml(options: DeleteObjectsOptions): string {
	return [
		"<Delete>",
		...options.objects.map((object) =>
			[
				"<Object>",
				`<Key>${escapeXml(object.key)}</Key>`,
				object.versionId
					? `<VersionId>${escapeXml(object.versionId)}</VersionId>`
					: "",
				object.eTag ? `<ETag>${escapeXml(object.eTag)}</ETag>` : "",
				"</Object>",
			].join(""),
		),
		options.quiet ? "<Quiet>true</Quiet>" : "",
		"</Delete>",
	].join("");
}

function escapeXml(value: string): string {
	return value.replace(/[<>&'"]/g, (char) => {
		switch (char) {
			case "<":
				return "&lt;";
			case ">":
				return "&gt;";
			case "&":
				return "&amp;";
			case "'":
				return "&apos;";
			case '"':
				return "&quot;";
			default:
				return char;
		}
	});
}

const MD5_SHIFTS = [
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
] as const;

const MD5_TABLE = Array.from({ length: 64 }, (_, index) =>
	Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000),
);

function md5Base64(encoder: TextEncoder, input: string): string {
	return bytesToBase64(md5(encoder.encode(input)));
}

function md5(input: Uint8Array): Uint8Array {
	const paddedLength = (((input.length + 8) >> 6) + 1) * 64;
	const padded = new Uint8Array(paddedLength);
	padded.set(input);
	padded[input.length] = 0x80;

	const view = new DataView(padded.buffer);
	const bitLength = input.length * 8;
	view.setUint32(paddedLength - 8, bitLength >>> 0, true);
	view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

	let a0 = 0x67452301;
	let b0 = 0xefcdab89;
	let c0 = 0x98badcfe;
	let d0 = 0x10325476;

	for (let offset = 0; offset < paddedLength; offset += 64) {
		let a = a0;
		let b = b0;
		let c = c0;
		let d = d0;

		for (let i = 0; i < 64; i++) {
			let f: number;
			let g: number;
			if (i < 16) {
				f = (b & c) | (~b & d);
				g = i;
			} else if (i < 32) {
				f = (d & b) | (~d & c);
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			} else {
				f = c ^ (b | ~d);
				g = (7 * i) % 16;
			}

			const nextD = d;
			d = c;
			c = b;
			b =
				(b +
					leftRotate(
						(a + f + MD5_TABLE[i] + view.getUint32(offset + g * 4, true)) >>> 0,
						MD5_SHIFTS[i],
					)) >>>
				0;
			a = nextD;
		}

		a0 = (a0 + a) >>> 0;
		b0 = (b0 + b) >>> 0;
		c0 = (c0 + c) >>> 0;
		d0 = (d0 + d) >>> 0;
	}

	const digest = new Uint8Array(16);
	const digestView = new DataView(digest.buffer);
	digestView.setUint32(0, a0, true);
	digestView.setUint32(4, b0, true);
	digestView.setUint32(8, c0, true);
	digestView.setUint32(12, d0, true);
	return digest;
}

function leftRotate(value: number, shift: number): number {
	return (value << shift) | (value >>> (32 - shift));
}

async function sha256Base64(
	crypto: Crypto,
	encoder: TextEncoder,
	input: string,
): Promise<string> {
	const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(input));
	return bytesToBase64(new Uint8Array(hashBuffer));
}

function bytesToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function isHashableBody(body: BodyInit): body is string | BufferSource {
	return (
		typeof body === "string" ||
		ArrayBuffer.isView(body) ||
		body instanceof ArrayBuffer
	);
}

function getHeaderNames(headers: Headers): string[] {
	const names: string[] = [];
	headers.forEach((_value, name) => {
		names.push(name);
	});
	return names;
}

function getSearchParamPairs(params: URLSearchParams): [string, string][] {
	const pairs: [string, string][] = [];
	params.forEach((value, key) => {
		pairs.push([key, value]);
	});
	return pairs;
}

async function hmac(
	crypto: Crypto,
	encoder: TextEncoder,
	key: string | BufferSource,
	string: string,
): Promise<ArrayBuffer> {
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		typeof key === "string" ? encoder.encode(key) : key,
		{ name: "HMAC", hash: { name: "SHA-256" } },
		false,
		["sign"],
	);
	return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(string));
}

async function hash(
	crypto: Crypto,
	encoder: TextEncoder,
	content: string | BufferSource,
): Promise<ArrayBuffer> {
	return crypto.subtle.digest(
		"SHA-256",
		typeof content === "string" ? encoder.encode(content) : content,
	);
}

const HEX_CHARS = "0123456789abcdef";

function buf2hex(arrayBuffer: ArrayBufferLike): string {
	const buffer = new Uint8Array(arrayBuffer);
	const out = new Array<string>(buffer.length * 2);
	for (let idx = 0; idx < buffer.length; idx++) {
		const n = buffer[idx] ?? 0;
		out[idx * 2] = HEX_CHARS.charAt((n >>> 4) & 0xf);
		out[idx * 2 + 1] = HEX_CHARS.charAt(n & 0xf);
	}
	return out.join("");
}

function encodeRfc3986(urlEncodedStr: string): string {
	return urlEncodedStr.replace(
		/[!'()*]/g,
		(c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
	);
}

function guessServiceRegion(
	url: URL,
	headers: Headers,
): [service: string, region: string] {
	const { hostname, pathname } = url;

	if (hostname.endsWith(".on.aws")) {
		const match = hostname.match(
			/^[^.]{1,63}\.lambda-url\.([^.]{1,63})\.on\.aws$/,
		);
		return match != null ? ["lambda", match[1] || ""] : ["", ""];
	}
	if (hostname.endsWith(".r2.cloudflarestorage.com")) {
		return ["s3", "auto"];
	}
	if (hostname.endsWith(".backblazeb2.com")) {
		const match = hostname.match(
			/^(?:[^.]{1,63}\.)?s3\.([^.]{1,63})\.backblazeb2\.com$/,
		);
		return match != null ? ["s3", match[1] || ""] : ["", ""];
	}
	if (hostname.endsWith(".linodeobjects.com")) {
		const match = hostname.match(
			/^(?:[^.]{1,63}\.)?([^.]{1,63})\.linodeobjects\.com$/,
		);
		return match != null ? ["s3", match[1] || ""] : ["", ""];
	}
	if (hostname.endsWith(".digitaloceanspaces.com")) {
		const match = hostname.match(
			/^(?:[^.]{1,63}\.)?([^.]{1,63})\.digitaloceanspaces\.com$/,
		);
		return match != null ? ["s3", match[1] || ""] : ["", ""];
	}
	const match = hostname
		.replace("dualstack.", "")
		.match(/([^.]{1,63})\.(?:([^.]{0,63})\.)?amazonaws\.com(?:\.cn)?$/);
	let service = (match && match[1]) || "";
	let region = match && match[2];

	if (region === "us-gov") {
		region = "us-gov-west-1";
	} else if (region === "s3" || region === "s3-accelerate") {
		region = "us-east-1";
		service = "s3";
	} else if (service === "iot") {
		if (hostname.startsWith("iot.")) {
			service = "execute-api";
		} else if (hostname.startsWith("data.jobs.iot.")) {
			service = "iot-jobs-data";
		} else {
			service = pathname === "/mqtt" ? "iotdevicegateway" : "iotdata";
		}
	} else if (service === "autoscaling") {
		const targetPrefix = (headers.get("X-Amz-Target") || "").split(".")[0];
		if (targetPrefix === "AnyScaleFrontendService") {
			service = "application-autoscaling";
		} else if (targetPrefix === "AnyScaleScalingPlannerFrontendService") {
			service = "autoscaling-plans";
		}
	} else if (region == null && service.startsWith("s3-")) {
		region = service.slice(3).replace(/^fips-|^external-1/, "");
		service = "s3";
	} else if (service.endsWith("-fips")) {
		service = service.slice(0, -5);
	} else if (region && /-\d$/.test(service) && !/-\d$/.test(region)) {
		[service, region] = [region, service];
	}

	return [HOST_SERVICES[service] || service, region || ""];
}

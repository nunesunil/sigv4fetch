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

const HOST_SERVICES = {
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
} as const satisfies Record<string, string>;

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

type SignInput = Request | { toString(): string };

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
	if (mergedInit.body == null && headers.has("Content-Type")) {
		mergedInit.body =
			body != null && headers.has("X-Amz-Content-Sha256")
				? body
				: await input.clone().arrayBuffer();
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

export class AwsClient {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken: string | undefined;
	service: string | undefined;
	region: string | undefined;
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
	body: BodyInit | null | undefined;
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken: string | undefined;
	service: string;
	region: string;
	cache: Map<string, ArrayBuffer>;
	datetime: string;
	signQuery: boolean | undefined;
	appendSessionToken: boolean;
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

		// header names from forEach are always lowercase
		this.signableHeaders = ["host", ...getHeaderNames(this.headers)]
			.filter((header) => allHeaders || !UNSIGNABLE_HEADERS.has(header))
			.sort();

		this.signedHeaders = this.signableHeaders.join(";");

		// headers are always trimmed:
		// https://fetch.spec.whatwg.org/#concept-header-value-normalize
		this.canonicalHeaders = this.signableHeaders
			.map(
				(header) =>
					`${header}:${header === "host" ? this.url.host : (this.headers.get(header) ?? "").replace(/\s+/g, " ")}`,
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
			.map(
				([k, v]) =>
					[
						encodeRfc3986(encodeURIComponent(k)),
						encodeRfc3986(encodeURIComponent(v)),
					] as [string, string],
			)
			.sort(([k1, v1], [k2, v2]) =>
				k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0,
			)
			.map(([k, v]) => `${k}=${v}`)
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
			`AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${this.credentialString}`,
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
			this.headers.get("X-Amz-Content-Sha256") ??
			(this.service === "s3" && this.signQuery ? "UNSIGNED-PAYLOAD" : null);
		if (hashHeader == null) {
			if (
				this.body &&
				typeof this.body !== "string" &&
				!("byteLength" in this.body)
			) {
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
	let out = "";
	for (const n of buffer) {
		out += HEX_CHARS[(n >>> 4) & 0xf];
		out += HEX_CHARS[n & 0xf];
	}
	return out;
}

function encodeRfc3986(urlEncodedStr: string): string {
	return urlEncodedStr.replace(
		/[!'()*]/g,
		(c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
	);
}

function guessServiceRegion(url: URL, headers: Headers): [string, string] {
	const { hostname, pathname } = url;

	if (hostname.endsWith(".on.aws")) {
		const match = hostname.match(
			/^[^.]{1,63}\.lambda-url\.([^.]{1,63})\.on\.aws$/,
		);
		return match != null ? ["lambda", match[1] ?? ""] : ["", ""];
	}
	if (hostname.endsWith(".r2.cloudflarestorage.com")) {
		return ["s3", "auto"];
	}
	if (hostname.endsWith(".backblazeb2.com")) {
		const match = hostname.match(
			/^(?:[^.]{1,63}\.)?s3\.([^.]{1,63})\.backblazeb2\.com$/,
		);
		return match != null ? ["s3", match[1] ?? ""] : ["", ""];
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
	let service = match?.[1] ?? "";
	let region = match?.[2];

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
		const targetPrefix = (headers.get("X-Amz-Target") ?? "").split(".")[0];
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

	return [
		HOST_SERVICES[service as keyof typeof HOST_SERVICES] ?? service,
		region ?? "",
	];
}

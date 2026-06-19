import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
	AwsClient,
	AwsV4Signer,
	S3Error,
	customS3Client,
	listObjectsV2,
} from "../dist/index.js";

const ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DATETIME = "20150830T123600Z";

describe("AwsV4Signer", () => {
	it("signs IAM ListUsers with AWS golden vector", async () => {
		const signer = new AwsV4Signer({
			url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			method: "GET",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "iam",
			region: "us-east-1",
			datetime: DATETIME,
		});

		const signed = await signer.sign();
		const auth = signed.headers.get("Authorization");

		assert.equal(
			auth,
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date, Signature=dad145687cde2dbf9684236b386711320b5997e4d31b3b5efe762858f46cc755",
		);
		assert.equal(signed.headers.get("X-Amz-Date"), DATETIME);
	});

	it("uses UNSIGNED-PAYLOAD for S3 header signing", async () => {
		const signer = new AwsV4Signer({
			url: "https://example-bucket.s3.amazonaws.com/object.txt",
			method: "PUT",
			body: "hello",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "s3",
			region: "us-east-1",
			datetime: DATETIME,
		});

		const signed = await signer.sign();
		assert.equal(signed.headers.get("X-Amz-Content-Sha256"), "UNSIGNED-PAYLOAD");
	});

	it("presigns S3 URLs with query signing", async () => {
		const signer = new AwsV4Signer({
			url: "https://example-bucket.s3.amazonaws.com/object.txt",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "s3",
			region: "us-east-1",
			datetime: DATETIME,
			signQuery: true,
		});

		const { url } = await signer.sign();
		assert.match(url.search, /X-Amz-Algorithm=AWS4-HMAC-SHA256/);
		assert.match(url.search, /X-Amz-Signature=[0-9a-f]{64}/);
		assert.match(url.search, /X-Amz-Expires=86400/);
		assert.equal(url.searchParams.get("X-Amz-Credential")?.includes(ACCESS_KEY), true);
	});

	it("hashes string bodies when X-Amz-Content-Sha256 is not set", async () => {
		const signer = new AwsV4Signer({
			url: "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/test/invocations",
			method: "POST",
			body: '{"hello":"world"}',
			headers: { "Content-Type": "application/json" },
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "lambda",
			region: "us-east-1",
			datetime: DATETIME,
		});

		const hash = await signer.hexBodyHash();
		assert.equal(
			hash,
			"93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588",
		);
	});

	it("reuses signing key cache across requests", async () => {
		const cache = new Map<string, ArrayBuffer>();
		const signer = new AwsV4Signer({
			url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			method: "GET",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "iam",
			region: "us-east-1",
			datetime: DATETIME,
			cache,
		});

		await signer.sign();
		assert.equal(cache.size, 1);

		const signer2 = new AwsV4Signer({
			url: "https://iam.amazonaws.com/?Action=ListRoles&Version=2010-05-08",
			method: "GET",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "iam",
			region: "us-east-1",
			datetime: DATETIME,
			cache,
		});
		await signer2.sign();
		assert.equal(cache.size, 1);
	});
});

describe("AwsClient.fetch retries", () => {
	it("retries 503 responses and eventually succeeds", async () => {
		let attempts = 0;

		const aws = new AwsClient({
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
			service: "iam",
			region: "us-east-1",
			retries: 2,
			initRetryMs: 1,
			api: {
				fetch: async () => {
					attempts++;
					if (attempts === 1) {
						return new Response("temporary failure", {
							status: 503,
							headers: { "Retry-After": "0" },
						});
					}
					return new Response("ok", { status: 200 });
				},
				Request: globalThis.Request,
				Headers: globalThis.Headers,
				crypto: globalThis.crypto,
				TextEncoder: globalThis.TextEncoder,
			},
		});

		const res = await aws.fetch(
			"https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			{
				method: "GET",
				aws: { datetime: DATETIME },
			},
		);

		assert.equal(res.status, 200);
		assert.equal(attempts, 2);
	});
});

describe("S3Error", () => {
	it("parses XML error responses from listObjectsV2", async () => {
		const client = customS3Client({
			host: "s3.us-east-1.amazonaws.com",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
		});

		client.s3.api.fetch = async () =>
			new Response(
				"<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
				{ status: 404, statusText: "Not Found" },
			);

		await assert.rejects(
			listObjectsV2(client, { bucket: "example-bucket" }),
			(error: unknown) => {
				assert.ok(error instanceof S3Error);
				assert.equal(error.code, "NoSuchKey");
				assert.equal(
					error.message,
					"NoSuchKey - The specified key does not exist.",
				);
				assert.equal(error.status, 404);
				return true;
			},
		);
	});

	it("falls back to HTTP status for non-XML errors", async () => {
		const client = customS3Client({
			host: "s3.us-east-1.amazonaws.com",
			accessKeyId: ACCESS_KEY,
			secretAccessKey: SECRET_KEY,
		});

		client.s3.api.fetch = async () =>
			new Response("not xml", { status: 500, statusText: "Server Error" });

		await assert.rejects(
			listObjectsV2(client, { bucket: "example-bucket" }),
			(error: unknown) => {
				assert.ok(error instanceof S3Error);
				assert.equal(error.code, "500");
				assert.equal(error.status, 500);
				return true;
			},
		);
	});
});

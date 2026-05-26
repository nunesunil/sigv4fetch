import { defineConfig } from "tsdown";

export default defineConfig({
	dts: true,
	format: "esm",
	platform: "neutral",
	minify: true,
});

import {
	assertExists,
	assertObjectMatch,
} from "https://deno.land/std@0.108.0/testing/asserts.ts"
import RegExpUri from "../src/RegExpUri.ts"

Deno.test("RegExpUri/exact/never/never/always", async () => {
	const { assertEquals } = await import("std/testing/asserts.ts")
	const re = new RegExpUri({
		exact: true,
		requireScheme: "never",
		requireDoubleSlash: "never",
		requireAuthority: "always",
	})
	const valid: string[] = [
		"username:password@example.org:80/path?query#fragment",
	]
	const invalid: string[] = [""]
	for (const target of valid) {
		const result = target.match(re)?.groups
		assertExists(result)
		assertObjectMatch(result, {
			uri: target,
			authority: "username:password@example.org:80",
			userinfo: "username:password",
			host: "example.org",
			port: "80",
			path: "/path",
			query: "query",
			fragment: "fragment",
		})
	}
	for (const target of invalid) {
		assertEquals(target.match(re)?.groups, undefined)
	}
})

Deno.test("RegExpUri/exact/undefined/undefined/undefined", async () => {
	const { assertEquals } = await import("std/testing/asserts.ts")
	const re = new RegExpUri({
		exact: true,
		requireScheme: undefined,
		requireDoubleSlash: undefined,
		requireAuthority: undefined,
	})
	const valid: string[] = [
		"username:password@example.org:80/path?query#fragment",
	]
	const invalid: string[] = [""]
	for (const target of valid) {
		const result = target.match(re)?.groups
		assertExists(result)
		assertObjectMatch(result, {
			uri: target,
			authority: "username:password@example.org:80",
			userinfo: "username:password",
			host: "example.org",
			port: "80",
			path: "/path",
			query: "query",
			fragment: "fragment",
		})
	}
	for (const target of invalid) {
		assertEquals(target.match(re)?.groups, undefined)
	}
})
import { escapeStringRegexp } from "https://deno.land/x/escape_string_regexp@v0.0.1/mod.ts"
import tlds from "./tlds.ts"

// <https://datatracker.ietf.org/doc/html/rfc3986#appendix-A>

const ALPHA = `a-zA-Z`
const DIGIT = `0-9`
const HEXDIG = `0-9a-fA-F`

const subDelims = `[!$&'()*+,;=]`
// const genDelims = `[:/?#\\[\\]@]`
// const reserved = `(?:${genDelims}|${subDelims})`
const unreserved = `(?:[${ALPHA}]|[${DIGIT}]|-|\\.|_|~)`
const pctEncoded = `%[${HEXDIG}][${HEXDIG}]`
const pchar = `(?:${unreserved}|${pctEncoded}|${subDelims}|:|@)`

// const segmentNzNc = `(?:${unreserved}|${pctEncoded}|${subDelims}|@)+`
const segmentNz = `(?:${pchar})+`
const segment = `(?:${pchar})*`

const pathEmpty = ``
const pathRootless = `${segmentNz}(?:/${segment})*`
// const pathNoscheme = `${segmentNzNc}(?:/${segment})*`
const pathAbsolute = `/(?:${segmentNz}(?:/${segment})*)?`
// const pathAbempty = `(?:/${segment})*`
// const pathNoauthority = `(?:${pathAbsolute}|${pathRootless}|${pathEmpty})`
// const path = `(?:${pathAbempty}|${pathAbsolute}|${pathNoscheme}|${pathRootless}|${pathEmpty})`

const regName = `(?:${unreserved}|${pctEncoded}|${subDelims})*`

const decOctet = `(?:[${DIGIT}]|[1-9][${DIGIT}]|1[${DIGIT}]{2}|2[0-4][${DIGIT}]|25[0-5])`
const ipv4Address = `${decOctet}.${decOctet}.${decOctet}.${decOctet}`
const h16 = `[${HEXDIG}]{1,4}`
const ls32 = `(?:${h16}:${h16}|${ipv4Address})`
const ipv6Address =
	`(?:` +
	`(?:${h16}:){6}${ls32}|` +
	`::(?:${h16}:){5}${ls32}|` +
	`(?:${h16})?::(?:${h16}:){4}${ls32}|` +
	`(?:(?:${h16}:){,1}${h16})?::(?:${h16}:){3}${ls32}|` +
	`(?:(?:${h16}:){,2}${h16})?::(?:${h16}:){2}${ls32}|` +
	`(?:(?:${h16}:){,3}${h16})?::${h16}:${ls32}|` +
	`(?:(?:${h16}:){,4}${h16})?::${ls32}|` +
	`(?:(?:${h16}:){,5}${h16})?::${h16}|` +
	`(?:(?:${h16}:){,6}${h16})?::` +
	`)`
const ipvFuture = `v[${HEXDIG}]+.(?:${unreserved}|${subDelims}|:)+`
const ipLiteral = `\\[(?:${ipv6Address}|${ipvFuture})\\]`

// RFC1034 3.5. Preferred name syntax
const letDig = `[${ALPHA}${DIGIT}]`
const letDigHyp = `[${ALPHA}${DIGIT}-]`
const ldhStr = `(?:${letDigHyp})+`
const label = `[${ALPHA}](?:${ldhStr}(?:${letDig})?)?`
const regNamePreferred = `(?:${label}\\.)+${label}`
const regNamePreferredWithKnownTlds = `(?:${label}\\.)+(?:${tlds.join("|")})`

const normalizeOptions = (
	options?: Partial<
		{ preset: keyof typeof RegExpUri.presets } & RegExpUri.Options
	>,
): RegExpUri.Options => {
	const preset = options?.preset ?? "canonical"
	const exact = options?.exact ?? false
	const groups = options?.groups ?? (exact ? "all" : "outmost")
	return { ...RegExpUri.presets[preset], ...options, exact, groups }
}

const generatePatternScheme = (options: RegExpUri.Options): string => {
	let pattern = `[${ALPHA}][${ALPHA}${DIGIT}+-.]*`
	const { allow, disallow } = options.schemes
	const syntax = new RegExp(`^${pattern}$`)
	if (allow && !disallow) {
		const invalid = allow.filter(scheme => !syntax.test(scheme))
		if (0 < invalid.length)
			throw new Error(
				`Some items in the scheme whitelist are in invalid syntax: ${invalid
					.map(scheme => `"${scheme}"`)
					.join(", ")}`,
			)
		pattern = `(?:${allow.map(escapeStringRegexp).join("|")})`
	} else if (!allow && disallow) {
		// If zero, it allows everything
		if (disallow.length !== 0) {
			const invalid = disallow.filter(scheme => !syntax.test(scheme))
			if (0 < invalid.length)
				throw new Error(
					`Some items in the scheme blacklist are in invalid syntax: ${invalid
						.map(scheme => `"${scheme}"`)
						.join(", ")}`,
				)
			const negation = `(?:${disallow.map(escapeStringRegexp).join("|")})`
			pattern = `(?:(?!${negation})${pattern}|${pattern}(?<!${negation}))`
		}
	} else {
		throw new Error(
			"The scheme whitelisting/blacklisting option cannot contain the both `allow` and `disallow` properties at the same time.",
		)
	}
	if (options.groups === "all") pattern = `(?<scheme>${pattern})`
	return pattern
}

const generateRegName = (options: RegExpUri.Options): string => {
	let pattern = regName
	if (options.usePreferredDomainNameSyntax) {
		pattern = regNamePreferred
		if (options.allowKnownTldsOnly) {
			pattern = regNamePreferredWithKnownTlds
		}
	}
	const { allow, disallow } = options.domains
	const syntax = new RegExp(`^${pattern}$`)
	if (allow && !disallow) {
		const invalid = allow.filter(domain => !syntax.test(domain))
		if (0 < invalid.length)
			throw new Error(
				`Some items in the domain whitelist are in invalid syntax: ${invalid
					.map(domain => `"${domain}"`)
					.join(", ")}`,
			)
		pattern = `(?:${allow.map(escapeStringRegexp).join("|")})`
	} else if (!allow && disallow) {
		// If zero, it allows everything
		if (disallow.length !== 0) {
			const invalid = disallow.filter(domain => !syntax.test(domain))
			if (0 < invalid.length)
				throw new Error(
					`Some items in the domain blacklist are in invalid syntax: ${invalid
						.map(domain => `"${domain}"`)
						.join(", ")}`,
				)
			const negation = `(?:${disallow.map(escapeStringRegexp).join("|")})`
			pattern = `(?:(?!${negation})${pattern}|${pattern}(?<!${negation}))`
		}
	} else {
		throw new Error(
			"The domain whitelisting/blacklisting option cannot contain the both `allow` and `disallow` properties at the same time.",
		)
	}
	return pattern
}

const generatePatternHost = (options: RegExpUri.Options): string => {
	const regName = generateRegName(options)
	let pattern = `(?:${ipLiteral}|${ipv4Address}|${regName})`
	if (options.groups === "all") pattern = `(?<host>${pattern})`
	return pattern
}

const generatePatternPort = (options: RegExpUri.Options): string => {
	let pattern = `[${DIGIT}]*`
	if (options.groups === "all") pattern = `(?<port>${pattern})`
	return pattern
}

const generatePatternUserinfo = (options: RegExpUri.Options): string => {
	let pattern = `(?:${unreserved}|${pctEncoded}|${subDelims}|:)*`
	if (options.groups === "all") pattern = `(?<userinfo>${pattern})`
	return pattern
}

const generatePatternAuthority = (options: RegExpUri.Options): string => {
	const host = generatePatternHost(options)
	const port = generatePatternPort(options)
	const userinfo = generatePatternUserinfo(options)
	let pattern = `(?:${userinfo}@)?${host}(?::${port})?`
	if (options.groups === "all") pattern = `(?<authority>${pattern})`
	return pattern
}

const generatePatternPathAbempty = (options: RegExpUri.Options): string => {
	let pattern = `(?:/${segment})*`
	if (options.groups === "all") pattern = `(?<pathAbempty>${pattern})`
	return pattern
}

const generatePatternPathNoauthority = (options: RegExpUri.Options): string => {
	let pattern = `(?:${pathAbsolute}|${pathRootless}|${pathEmpty})`
	if (options.groups === "all") pattern = `(?<pathNoauthority>${pattern})`
	return pattern
}

const generatePatternSchemeHierPart = (options: RegExpUri.Options): string => {
	const scheme = generatePatternScheme(options)
	const authority = generatePatternAuthority(options)
	const pathAbempty = generatePatternPathAbempty(options)
	const pathNoauthority = generatePatternPathNoauthority(options)
	const { requireScheme, requireDoubleSlash, requireAuthority } = options
	switch (requireAuthority) {
		case "always": // authority
			switch (requireScheme) {
				case "always": // scheme
					return `${scheme}://${authority}${pathAbempty}`
				case "never": // scheme
					switch (requireDoubleSlash) {
						case "always": // double slash
							return `//${authority}${pathAbempty}`
						case "never": // double slash
							return `${authority}${pathAbempty}`
						default: // double slash
							return `(?://)?${authority}${pathAbempty}`
					}
				default: // scheme
					switch (requireDoubleSlash) {
						case "always": // double slash
							return `(?:${scheme}:)?//${authority}${pathAbempty}`
						case "never": // double slash
							return `(?:${scheme}://)?${authority}${pathAbempty}`
						default: // double slash
							return `(?:(?:${scheme}:)?//)?${authority}${pathAbempty}`
					}
			}
		case "never": // authority
			switch (requireScheme) {
				case "always": // scheme
					return `${scheme}:${pathNoauthority}`
				case "never": // scheme
					return `${pathNoauthority}`
				default: // scheme
					return `(?:${scheme}:)?${pathNoauthority}`
			}
		default: // authority
			switch (requireScheme) {
				case "always": // scheme
					return `${scheme}:(?://${authority}${pathAbempty}|${pathNoauthority})`
				case "never": // scheme
					switch (requireDoubleSlash) {
						case "always": // double slash
							return `(?://${authority}${pathAbempty}|${pathNoauthority})`
						case "never": // double slash
							return `(?:${authority}${pathAbempty}|${pathNoauthority})`
						default: // double slash
							return `(?:(?://)?${authority}${pathAbempty}|${pathNoauthority})`
					}
				default: // scheme
					switch (requireDoubleSlash) {
						case "always": // double slash
							return `(?:${scheme}:)?(?://${authority}${pathAbempty}|${pathNoauthority})`
						case "never": // double slash
							return `(?:${scheme}:(?://${authority}${pathAbempty}|${pathNoauthority})|(?:${authority}${pathAbempty}|${pathNoauthority}))`
						default: // double slash
							return `(?:${scheme}:(?://${authority}${pathAbempty}|${pathNoauthority})|(?:(?://)?${authority}${pathAbempty}|${pathNoauthority}))`
					}
			}
	}
}

const generatePatternQuery = (options: RegExpUri.Options): string => {
	let pattern = `(?:${pchar}|/|\\?)+`
	if (options.allowEmptyQuery) pattern = `(?:${pattern})?`
	if (options.groups === "all") pattern = `(?<query>${pattern})`
	return `(?:\\?${pattern})?`
}

const generatePatternFragment = (options: RegExpUri.Options): string => {
	let pattern = `(?:${pchar}|/|\\?)+`
	if (options.allowEmptyFragment) pattern = `(?:${pattern})?`
	if (options.groups === "all") pattern = `(?<fragment>${pattern})`
	return `(?:#${pattern})?`
}

const generatePatternUri = (options: RegExpUri.Options): string => {
	const schemeHierPart = generatePatternSchemeHierPart(options)
	const query = generatePatternQuery(options)
	const fragment = generatePatternFragment(options)
	let pattern = `${schemeHierPart}${query}${fragment}`
	if (options.groups !== "none") pattern = `(?<uri>${pattern})`
	return pattern
}

const generatePattern = (options: RegExpUri.Options): string => {
	let pattern = generatePatternUri(options)
	if (options.exact) pattern = `^${pattern}$`
	return pattern
}

class RegExpUri extends RegExp {
	options: RegExpUri.Options
	constructor(
		options?:
			| Partial<{ preset: keyof typeof RegExpUri.presets } & RegExpUri.Options>
			| RegExpUri,
		flags?: string,
	) {
		const optionsDetailed =
			options instanceof RegExpUri ? options.options : normalizeOptions(options)
		super(generatePattern(optionsDetailed), flags)
		this.options = optionsDetailed
	}
	exec(string: string): RegExpExecArray | null {
		const result = RegExp.prototype.exec.call(this, string)
		if (result?.groups) {
			if (
				"pathAbempty" in result.groups &&
				"pathNoauthority" in result.groups
			) {
				const path = result.groups.pathAbempty ?? result.groups.pathNoauthority
				const query = result.groups.query
				const fragment = result.groups.fragment
				delete result.groups.pathAbempty
				delete result.groups.pathNoauthority
				delete result.groups.query
				delete result.groups.fragment
				result.groups.path = path
				result.groups.query = query
				result.groups.fragment = fragment
			}
		}
		return result
	}
}

namespace RegExpUri {
	export type Options = {
		/**
		 * A whitelist or a blacklist of schemes.
		 *
		 * Default: `{ disallow: [] }`.
		 */
		schemes: Whitelist<string> | Blacklist<string>

		/**
		 * A whitelist or a blacklist of domains.
		 *
		 * Default: `{ disallow: [] }`.
		 */
		domains: Whitelist<string> | Blacklist<string>

		/**
		 * Whether the scheme part must be present. `undefined` allows both cases.
		 *
		 * [RFC3986 ***does*** require](https://datatracker.ietf.org/doc/html/rfc3986#section-3), so setting this option to `"never"` or `undefined` shall get you out of the legal syntax of URI.
		 *
		 * Default: `"always"`.
		 */
		requireScheme: "always" | "never" | undefined

		/**
		 * Whether the double slash must be present, when the scheme part is missing but the authority part is present. `undefined` allows both cases. This setting is only meaningful when `requireScheme` is `"never"` or `undefined.
		 *
		 * [RFC3986 ***does*** require it as long as the authority part is present](https://datatracker.ietf.org/doc/html/rfc3986#section-3), so setting this option to `"never"` or `undefined` shall get you out of the legal syntax of URI.
		 *
		 * Default: `"always"`.
		 */
		requireDoubleSlash: "always" | "never" | undefined

		/**
		 * Whether the authority part must be present. `undefined` allows both cases.
		 *
		 * Default: `undefined`.
		 */
		requireAuthority: "always" | "never" | undefined

		/**
		 * Whether to use [RFC1034 3.5. Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5).
		 *
		 * Default: `false`.
		 */
		usePreferredDomainNameSyntax: boolean

		/**
		 * Whether to verify given domain name has a well-known TLD in the IANA's list. Only meaningful when `usePreferredDomainNameSyntax` is `true`.
		 *
		 * Default: `false`.
		 */
		allowKnownTldsOnly: boolean

		/**
		 * Whether URIs can be relative reference.
		 *
		 * Default: `true`.
		 */
		allowRelative: boolean

		/**
		 * Whether to allow the query part to be without its content.
		 *
		 * Default: `true`.
		 */
		allowEmptyQuery: boolean

		/**
		 * Whether to allow the fragment part to be without its content.
		 *
		 * Default: `true`.
		 */
		allowEmptyFragment: boolean

		/**
		 * Enables exact match pattern. It wraps the `RegExp` pattern with `^` and `$`.
		 *
		 * Default: `false`.
		 */
		exact: boolean

		/**
		 * Enables named capture groups. See {@link NamedCaptureGroups `RegExpUri.NamedCaptureGroups`} to know what's in the box.
		 *
		 * `"outmost"` should fit for some usage e.g. splitting a plaintext by URIs using [`String.prototype.split`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/split).
		 *
		 * Default: `"all"` if `exact` is `true`, `"outmost"` otherwise.
		 */
		groups: "all" | "outmost" | "none"
	}

	export type NamedCaptureGroups = {
		uri: string
		scheme: string | undefined
		authority: string | undefined
		userinfo: string | undefined
		host: string | undefined
		port: string | undefined
		path: string | undefined
		query: string | undefined
		fragment: string | undefined
	}

	export type Whitelist<T> = { allow: T[]; disallow?: never }
	export type Blacklist<T> = { allow?: never; disallow: T[] }

	export const presets = {
		canonical: {
			schemes: { disallow: [] },
			domains: { disallow: [] },
			requireScheme: "always",
			requireDoubleSlash: "always",
			requireAuthority: undefined,
			usePreferredDomainNameSyntax: false,
			allowKnownTldsOnly: false,
			allowRelative: true,
			allowEmptyQuery: true,
			allowEmptyFragment: true,
		} as Omit<Options, "exact" | "groups">,
		convenient: {
			schemes: { allow: ["https", "http"] },
			domains: { disallow: [] },
			requireScheme: undefined,
			requireDoubleSlash: "never",
			requireAuthority: "always",
			usePreferredDomainNameSyntax: true,
			allowKnownTldsOnly: true,
			allowRelative: false,
			allowEmptyQuery: false,
			allowEmptyFragment: false,
		} as Omit<Options, "exact" | "groups">,
	} as const
}

export default RegExpUri
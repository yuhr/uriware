import RegExpUri from "../src/RegExpUri.ts"

Deno.test("RegExpUri", async () => {
  const { assertEquals } = await import("std/testing/asserts.ts")
  // TODO: write tests
  const re = new RegExpUri({ preset: "canonical", exact: true })
})
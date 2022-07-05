import { build, emptyDir } from "https://deno.land/x/dnt@0.27.0/mod.ts"
import packageJson from "./package.json" assert { type: "json" }

await emptyDir("./dist")

await build({
  entryPoints: ["./src/index.ts"],
  outDir: "./dist",
  shims: {
    // see JS docs for overview and more options
    deno: true,
  },
  package: packageJson,
  packageManager: "pnpm",
  typeCheck: false,
  test: false,
})

// post build steps
Deno.copyFileSync("LICENSE", "./dist/LICENSE")
Deno.copyFileSync("README.md", "./dist/README.md")
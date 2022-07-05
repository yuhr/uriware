import { getAllDomains } from "https://deno.land/x/domain@v0.1.0/mod.ts"

const tlds = getAllDomains()
  .map(tld => tld.substring(1)) // .org -> org
  .sort((a, b) => b.length - a.length) // sort longer to shorter, as first match wins

export default tlds
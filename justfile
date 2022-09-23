@_:
	just --list

test:
	deno test --import-map=tests/import-map.json --allow-net tests

bundle:
	deno run -A bundle.ts

pack: bundle
	cd dist && npm pack
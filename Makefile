.PHONY: build typecheck test bench clean check

build:
	npm run build

typecheck:
	npm run typecheck

test:
	npm test

bench:
	npm run bench

clean:
	npm run clean

check: typecheck test bench

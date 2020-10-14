DAGGO ?= go

DAGTAG_NOSANCHECKS := nosanchecks_DAGger nosanchecks_qringbuf

.PHONY: $(MAKECMDGOALS)

build: dataset
	@mkdir -p bin/
	rm bin/fil-discover-check
	$(DAGGO) build \
		-o bin/fil-discover-check ./cmd/fil-discover-check
	$(DAGGO) run github.com/GeertJohan/go.rice/rice append --exec bin/fil-discover-check -i ./cmd/fil-discover-check

dataset:
	mkdir -p tmp/data
	[ -r tmp/data/fil_discover_full.dat ] || curl https://fil-chain-snapshots-fallback.s3.amazonaws.com/fil_discover_full.dat > tmp/data/fil_discover_full.dat

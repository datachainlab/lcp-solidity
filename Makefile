SOLC_VERSION ?= 0.8.19
FORGE ?= forge

.PHONY: proto-sol
proto-sol:
ifndef SOLPB_DIR
	$(error SOLPB_DIR is not specified)
else
	./solpb.sh
endif

.PHONY: test
test:
	@$(FORGE) test -vvvv --gas-report --ffi --use solc:$(SOLC_VERSION)

.PHONY: fmt
fmt:
	@$(FORGE) fmt $(FORGE_FMT_OPTS) \
		./contracts/*.sol \
		./test

.PHONY: check-fmt
check-fmt:
	@$(MAKE) FORGE_FMT_OPTS=--check fmt

SOLC_VERSION=0.8.20
FORGE=forge
TEST_UPGRADEABLE=false

.PHONY: build
build:
	@FOUNDRY_PROFILE=ir $(FORGE) build --sizes --skip test --use solc:$(SOLC_VERSION)

.PHONY: clean
clean:
	@$(FORGE) clean

.PHONY: test
test:
	@TEST_UPGRADEABLE=$(TEST_UPGRADEABLE) $(FORGE) test -vvvv --gas-report --ffi --use solc:$(SOLC_VERSION)

.PHONY: coverage
coverage:
	@$(FORGE) coverage --ffi --use solc:$(SOLC_VERSION)

.PHONY: fmt
fmt:
	@$(FORGE) fmt $(FORGE_FMT_OPTS) \
		./contracts/*.sol \
		./test

.PHONY: check-fmt
check-fmt:
	@$(MAKE) FORGE_FMT_OPTS=--check fmt

.PHONY: lint
lint:
	@npx solhint 'contracts/*.sol'
	@$(MAKE) FORGE_FMT_OPTS=--check fmt

.PHONY: proto-sol
proto-sol:
ifndef SOLPB_DIR
	$(error SOLPB_DIR is not specified)
else
	./solpb.sh
endif

# lcp-solidity

lcp-solidity is an implementation of [lcp client](https://docs.lcp.network/protocol/lcp-client) in solidity. It can be integrated with [ibc-solidity](https://github.com/hyperledger-labs/yui-ibc-solidity).

An e2e demo is available [here](https://github.com/datachainlab/cosmos-ethereum-ibc-lcp).

**DISCLAIMER: This repository has not been audited yet, so use it at your own risk.**

## Gas cost

- registerEnclaveKey: 550k: first registration in the client or signing key changed(very rare)
- registerEnclaveKey: 210k
- updateState: 190k
- verifyMembership: 15k
- verifyNonMembership: 14k

## How to generate test data

You can find the LCP commitment data for the test in `./test/data`.

Also, you can generate the test data with the following steps:
```
$ git clone https://github.com/datachainlab/lcp-cgen
$ cd ./lcp-cgen
# if execute it under non-sgx environment, you must enable anoption `--features=simulation`
$ cargo build -r --features=simulation
# Example for using RA simulation
$ export LCP_PATH=/path/to/lcp-repo
$ ./target/release/lcp-cgen \
    --simulate \
    --signing_cert_path=${LCP_PATH}/tests/certs/signing.crt.der \
    --signing_key=${LCP_PATH}/tests/certs/signing.key \
    --enclave=${LCP_PATH}/bin/enclave.signed.so \
    --out=/path/to/testdatadir \
    --commands wait_blocks:1 update_client verify_channel wait_blocks:1 update_client verify_packet
```

-include .env
.PHONY: install deploy-contracts test coverage coverage-html

install:
	forge install

deploy:
	forge script script/Deploy.s.sol \
		--rpc-url ${ETH_RPC_URL} --private-key ${PRIVATE_KEY} --broadcast -vvv

deploy-anvil:
	forge script script/Deploy.s.sol \
		--rpc-url ${ANVIL_RPC_URL} --private-key ${ANVIL_PRIVATE_KEY} --broadcast -vvv

deploy-verify:
	forge script script/Deploy.s.sol \
		--rpc-url ${ETH_RPC_URL} --private-key ${PRIVATE_KEY} --etherscan-api-key ${ETHERSCAN_KEY} --verify --broadcast -vvv

test:
	forge test

coverage:
	forge coverage

coverage-html:
	forge coverage --report lcov
	genhtml lcov.info --branch-coverage --output-dir coverage

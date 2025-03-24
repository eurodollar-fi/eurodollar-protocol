# Eurodollar Protocol

## System overview

The Eurodollar Protocol consists of two types of tokens, USDE a compliant USD stablecoin and InvestToken (EUI), for compliant yield tokens, and a price oracle, which allows seamless conversion between the two tokens. The system is designed to be compliant with EU regulation regarding stablecoins (MICA) and security tokens (MIFID2).

The solutions utilizes OpenZeppelin contracts for the tokens, to ensure upgradeability is implemented.

### USDE

The stablecoin ERC20 token contract. Implements following functionality:

- Transfers of funds between non-blacklisted addresses
- Minting
- Burning, with or without provided signature
- Recovering of funds
- Pausing
- UUPS upgradeablity
- AccessControl for relevant functions

### InvestToken

The yield-bearing ERC4626 token contract. Implements following functionality:

- Transfers of funds between whitelisted addresses
- ERC4626 standard functions for flipping between it and the stablecoin according to the conversion rate provided by YieldOracle
- Minting
- Burning, with or without provided signature
- Recovering of funds
- Pausing
- UUPS upgradeablity
- AccessControl for relevant functions

### YieldOracle

Smart-contract for providing the conversion price between the stablecoin and an yield bearing token. Implements following functionality:

- Current Price - the latest conversion price. This is used when users flip from stablecoinf to invest token, to ensure they do not accrue fees based on yields that were accumulated before depositing.
- Previous Price - we maintain both conversion prices, a current price, and the last price before that in order ensure that users who flip from invest token to stablecoin do not accrue *today's* yield, but gets *yesterday's* conversion rate. This is due to a redemption delay on the backend fiat systems.
- Last Update - timestamp of the last price update used to check against guard rail delay, below.
- Guard rail to ensure that a faulty oracle bot does not increase price arbitrarily `maxPriceIncrease`.
- Delay - guard rail to ensure that if an oracle bot is faulty that price updates can only be pushed at a certain time interval.
- Price update functions - making sure `delay` since last update is not violated and that the new price's increase does exceed `maxIncrease`.
- Conversion view functions
- Pausing
- AccessControl for relevant functions

### Validator

Smart-contract keeping track of the transfer persmission state of an address. Each address can be in 1 of 3 states:

- `WHITELISTED`
- `BLACKLISTED`
- `VOID` (default) - considered neither whitelisted or blacklisted

These states have corresponding set functions (allowing one or more accounts) and are relevant for the view functions:

- `isValid(from, to)` keeping track of the blacklisted state of the `from` and `to` address; it returns false if either of `from` or `to` is `BLACKLISTED`, except for the cases corresponding to burning, when `to` would be null address 0x0

- `isValidStrict(from, to)` keeping track of the whitelisted state of the `from` and `to` address; it returns false if either of `from` or `to` is not `WHITELISTED`, except for the cases corresponding to minting to `WHITELISTED` address, when `from` would be null address,or burning, when `to` would be null address

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation

1. Install dependencies:
```bash
forge install
```

### Building

1. Compile the contracts:
```bash
forge build
```

### Deployment

1. Copy `.env.example` to `.env` and set your private key.

2. Check `script/Deploy.s.sol` if you want to modify parameters.

3. Run deployment script. For example, testing locally (anvil environment):
```bash
forge script script/Deploy.s.sol
    --fork-url http://localhost:8545
    --broadcast
```
Or deploy Onchain:
```bash
forge script script/Deploy.s.sol --rpc-url holesky --broadcast --verify
```

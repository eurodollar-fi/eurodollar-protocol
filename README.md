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

## Deployment Options

The project includes three deployment scripts for different use cases:

1. **Standard Deployment** (`Deploy.s.sol`) - Simple deployment without address predictability
2. **Deterministic Deployment** (`DeployDeterministic.s.sol`) - CREATE2-based deployment for deterministic addresses
3. **Blacklist Loader** (`BlacklistLoader.sol`) - Utility to populate the blacklist from a JSON file

### Environment Setup

Copy `.env.example` to `.env` and configure the following variables:

```
PRIVATE_KEY=0x          # Your deployment private key
HOLESKY_RPC_URL=        # Holesky testnet RPC endpoint
BNB_TESTNET_RPC_URL=    # BNB testnet RPC endpoint  
ETHERSCAN_API_KEY=      # Etherscan API key for verification
BSCSCAN_API_KEY=        # BSCScan API key for verification
VALIDATOR_ADDRESS=0x    # Validator contract address (for blacklist loader)
NETWORK=                # Network name (for deterministic deployment)
```

### 1. Standard Deployment

Use this method for standard deployments without address predictability. This is simpler and uses less gas.

```bash
# Local deployment
forge script script/Deploy.s.sol --fork-url http://localhost:8545 --broadcast

# Testnet deployment (Holesky)
forge script script/Deploy.s.sol --rpc-url holesky --broadcast

# Testnet deployment with verification
forge script script/Deploy.s.sol --rpc-url holesky --broadcast --verify
```

### 2. Deterministic Deployment

Use this method when you need predictable contract addresses across different networks. This is useful for cross-chain deployments or when you need to know contract addresses in advance.

```bash
# Set network name in .env
NETWORK=holesky

# Local deployment
forge script script/DeployDeterministic.s.sol --fork-url http://localhost:8545 --broadcast

# Testnet deployment (Holesky)
forge script script/DeployDeterministic.s.sol --rpc-url holesky --broadcast

# Testnet deployment with verification
forge script script/DeployDeterministic.s.sol --rpc-url holesky --broadcast --verify
```

The deterministic deployment will save the contract addresses to a JSON file at `./broadcast/{network}-deployment.json` for future reference.

Example output file:
```json
{
  "network": "holesky",
  "deployer": "0x123...",
  "deploymentTime": 1712345678,
  "contracts": {
    "validator": "0x456...",
    "usde": {
      "proxy": "0x789...",
      "implementation": "0xabc..."
    },
    "yieldOracle": "0xdef...",
    "investToken": {
      "proxy": "0xfed...",
      "implementation": "0xcba..."
    }
  }
}
```

### 3. Blacklist Loader

After deploying the Validator contract, you can populate it with blacklisted addresses from a JSON file.

1. First, create a `blacklist.json` file in the project root with an array of addresses:

```json
[
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333"
]
```

2. Set the `VALIDATOR_ADDRESS` in your `.env` file to the deployed Validator contract address.

3. Run the blacklist loader:

```bash
# Local
forge script script/BlacklistLoader.s.sol --fork-url http://localhost:8545 --broadcast

# Testnet (Holesky)
forge script script/BlacklistLoader.s.sol --rpc-url holesky --broadcast
```

The script will process addresses in batches of 100 to avoid gas limits.
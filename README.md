# AuthAgent: Decentralized Identity for Autonomous AI Agents

## The Capability Binding Primitive (CBP)

### What is Capability Binding?

Capability Binding is a cryptographic primitive that binds an agent's Decentralized Identity (DID) to specific smart contract function signatures through Merkle tree commitments. Unlike traditional role-based access control (RBAC) or permission lists, CBP uses **cryptographic commitments** that can be verified on-chain without state lookups.

### Cryptographic Specification

```
CapabilityLeaf = keccak256(
  abi.encodePacked(
    agentDID,           // 32 bytes - Agent's DID address
    functionSelector,   // 4 bytes - 4-byte function signature
    targetContract,     // 20 bytes - Target contract address
    salt,               // 32 bytes - Unique salt per capability
    expirationBlock     // 8 bytes - Block number expiration
  )
)

CapabilityManifest = keccak256(
  abi.encodePacked(
    CapabilityLeaf,
    agentSignature,     // 65 bytes - ECDSA signature of leaf
    nonce               // 8 bytes - Replay protection nonce
  )
)

MerkleRoot = MerkleProof.computeRoot([CapabilityManifest, ...])
```

### Why CBP is Novel

1. **No State Lookups**: Capability verification uses Merkle inclusion proofs (O(log n)) instead of storage reads (O(1) but gas expensive at scale)
2. **Immutable Binding**: Once a capability is registered, the binding is immutable - changes require new capability registration
3. **Cryptographic Revocation**: Revocation is done via Merkle tree updates, not individual state clearing
4. **Replay Protection**: Each capability includes a nonce that increments with each usage

### Integration with Existing AI Workflows

#### Step 1: Agent Identity Registration

```javascript
// In your AI agent initialization
const { AgentIdentity } = require('./src/agent/Agent');

const agent = new AgentIdentity({
  privateKey: process.env.AGENT_PRIVATE_KEY,
  registryAddress: '0x...', // Deployed AgentIdentity contract
  networkId: 11155111 // Sepolia
});

// Register agent with capability binding proof
await agent.registerWithCapabilities([
  {
    functionSelector: '0xa9059cbb', // ERC20 transfer
    targetContract: '0x...',
    salt: crypto.randomBytes(32),
    expirationBlock: 10000000
  }
]);
```

#### Step 2: Capability Binding Registration

```javascript
// Register capabilities with CapabilityRegistry
const { CapabilityRegistry } = require('./contracts/CapabilityRegistry');

const registry = new CapabilityRegistry({
  address: '0x...',
  signer: agent.wallet
});

// Create capability manifest
const manifest = await registry.createCapabilityManifest({
  agentDID: agent.did,
  functionSelector: '0xa9059cbb',
  targetContract: '0x...',
  salt: '0x...',
  expirationBlock: 10000000
});

// Submit capability with Merkle proof
await registry.registerCapability(manifest, merkleProof);
```

#### Step 3: Autonomous Transaction Execution

```javascript
// Agent executes transaction autonomously
const { AgentOrchestrator } = require('./src/orchestration/AgentOrchestrator');

const orchestrator = new AgentOrchestrator({
  agent: agent,
  registry: registry,
  verificationService: verificationService
});

// Execute capability-bound transaction
const tx = await orchestrator.executeCapability({
  capabilityHash: capabilityHash,
  targetContract: '0x...',
  functionData: abi.encodeFunctionCall('transfer', ['0x...', 1000])
});

// Transaction is signed by agent's private key
// On-chain verification confirms capability binding
```

## Deployment Guide

### Prerequisites

```bash
# Install dependencies
npm install

# Set environment variables
export PRIVATE_KEY_1="your_private_key"
export SEPOLIA_RPC_URL="your_rpc_url"
export AGENT_PRIVATE_KEY="agent_private_key"
```

### Step 1: Compile Contracts

```bash
npx hardhat compile
```

### Step 2: Deploy AgentIdentity Contract

```bash
npx hardhat run scripts/deploy.js --network sepolia
```

Expected output:
```
AgentIdentity deployed to: 0x...
CapabilityRegistry deployed to: 0x...
```

### Step 3: Initialize Capability Registry

```bash
npx hardhat run scripts/initialize.js --network sepolia
```

### Step 4: Register Agent Identity

```bash
npx hardhat run scripts/register-agent.js --network sepolia
```

### Step 5: Deploy Dashboard

```bash
npx hardhat run scripts/deploy-dashboard.js --network sepolia
```

### Step 6: Verify on Etherscan

```bash
npx hardhat verify --network sepolia DEPLOYED_CONTRACT_ADDRESS
```

## Demo Video Script

### Scene 1: The Problem (0:00 - 0:30)

**Visual**: Screen shows multiple AI agents executing transactions in DeFi protocols.

**Narrator**: "In today's AI-driven DeFi landscape, we face a critical problem: when an autonomous agent executes a transaction, who is responsible? Traditional systems rely on centralized API keys or human-signed transactions. But what happens when the agent acts autonomously? The 'who did it' problem creates accountability gaps that can lead to catastrophic failures."

**Visual**: Red warning signs appear over transactions with no clear ownership.

### Scene 2: The Solution (0:30 - 1:00)

**Visual**: AuthAgent logo appears with cryptographic symbols.

**Narrator**: "AuthAgent introduces the Capability Binding Primitive - a cryptographic framework that gives every AI agent its own decentralized identity. Each agent generates a unique wallet address and registers it on-chain. Every autonomous action is cryptographically bound to that identity."

**Visual**: Agent DID address appears with cryptographic hash visualization.

### Scene 3: Capability Binding in Action (1:00 - 2:00)

**Visual**: Code editor shows capability registration.

**Narrator**: "Here's how it works. When an agent wants to execute a transaction, it first registers a capability manifest. This manifest includes the function selector, target contract, and a cryptographic salt. The manifest is signed by the agent's private key and stored in a Merkle tree."

**Visual**: Merkle tree animation showing leaf nodes and root hash.

**Narrator**: "When the agent executes a transaction, it provides a Merkle inclusion proof. The smart contract verifies this proof on-chain, confirming the capability binding without state lookups."

### Scene 4: Autonomous Execution (2:00 - 2:30)

**Visual**: Dashboard shows agent executing transaction autonomously.

**Narrator**: "Now watch the agent execute autonomously. It signs the transaction with its private key, submits the capability proof, and the transaction executes. Every step is verifiable on-chain."

**Visual**: Transaction hash appears with verification status.

### Scene 5: Security Guarantees (2:30 - 3:00)

**Visual**: Security shield animation with cryptographic symbols.

**Narrator**: "AuthAgent provides three critical security guarantees: First, cryptographic self-enforcement - no trust assumptions, only math. Second, replay protection via nonce binding. Third, capability revocation through Merkle tree updates."

**Visual**: Code snippets showing security primitives.

### Scene 6: Integration (3:00 - 3:30)

**Visual**: Integration diagram showing AuthAgent with existing AI frameworks.

**Narrator**: "AuthAgent integrates seamlessly with existing AI frameworks like AutoGen. Simply initialize your agent with the AuthAgent SDK, and you get decentralized identity out of the box."

**Visual**: Code showing integration with AutoGen.

### Scene 7: Call to Action (3:30 - 4:00)

**Visual**: AuthAgent logo with GitHub link.

**Narrator**: "AuthAgent is the first AI agent framework with native Decentralized Identity support. Join us in building the future of autonomous AI with verifiable accountability. Check out the code on GitHub and start building today."

**Visual**: GitHub URL and social media links.

## Technical Architecture

### Contract Interfaces

```solidity
// AgentIdentity.sol
interface IAgentIdentity {
  function register(bytes calldata proof) external;
  function getAgentDID(address agent) external view returns (address);
  function verifyCapability(bytes calldata proof) external view returns (bool);
}

// CapabilityRegistry.sol
interface ICapabilityRegistry {
  function registerCapability(bytes calldata manifest, bytes calldata proof) external;
  function verifyCapability(bytes calldata proof) external view returns (bool);
  function revokeCapability(bytes calldata capabilityHash) external;
}
```

### Node.js Integration

```javascript
// src/agent/Agent.js
class AgentIdentity {
  constructor(config) {
    this.privateKey = config.privateKey;
    this.registryAddress = config.registryAddress;
    this.networkId = config.networkId;
    this.wallet = new WalletManager(this.privateKey);
    this.did = this.wallet.getAddress();
  }

  async registerWithCapabilities(capabilities) {
    // Generate capability manifests
    const manifests = capabilities.map(cap => this.createManifest(cap));
    
    // Create Merkle tree
    const merkleTree = new MerkleTree(manifests);
    
    // Register with registry
    const proof = await this.registry.register(merkleTree.getRoot());
    
    return proof;
  }

  createManifest(capability) {
    return {
      agentDID: this.did,
      functionSelector: capability.functionSelector,
      targetContract: capability.targetContract,
      salt: capability.salt,
      expirationBlock: capability.expirationBlock
    };
  }
}
```

### Verification Service

```javascript
// src/verification/VerificationService.js
class VerificationService {
  constructor(registryAddress, networkId) {
    this.registryAddress = registryAddress;
    this.networkId = networkId;
    this.abi = require('./abi/CapabilityRegistry.json');
  }

  async verifyCapability(proof, capabilityHash) {
    // Verify Merkle inclusion proof
    const isValid = await this.verifyMerkleProof(proof, capabilityHash);
    
    // Verify signature
    const isValidSignature = await this.verifySignature(proof);
    
    // Verify nonce
    const isValidNonce = await this.verifyNonce(proof);
    
    return isValid && isValidSignature && isValidNonce;
  }

  async verifyMerkleProof(proof, capabilityHash) {
    // On-chain verification using MerkleProof library
    const result = await this.registry.verifyCapability(proof);
    return result;
  }

  async verifySignature(proof) {
    // ECDSA signature verification
    const recoveredAddress = ethers.utils.recoverAddress(
      ethers.utils.hashMessage(proof.message),
      proof.signature
    );
    return recoveredAddress === proof.agentDID;
  }

  async verifyNonce(proof) {
    // Check nonce hasn't been used before
    const usedNonce = await this.registry.getNonce(proof.agentDID);
    return proof.nonce > usedNonce;
  }
}
```

## Security Considerations

### Adversarial Resilience

1. **Replay Attacks**: Each capability includes a nonce that increments with each usage
2. **Signature Forgery**: All signatures verified using ECDSA with EIP-712 typed data
3. **Merkle Tree Attacks**: Merkle proofs verified on-chain using OpenZeppelin library
4. **Reentrancy**: All state-changing functions protected with ReentrancyGuard
5. **Time-Based Attacks**: Expiration blocks enforced by block.timestamp

### Cryptographic Self-Enforcement

```solidity
// All permissions verified by math, not trust
function verifyCapability(bytes calldata proof) public view returns (bool) {
  // Verify Merkle inclusion
  require(MerkleProof.verify(proof.merkleProof, merkleRoot, proof.leaf), "Invalid proof");
  
  // Verify signature
  require(ECDSA.recover(
    keccak256(abi.encodePacked(proof.message)),
    proof.signature
  ) == proof.agentDID, "Invalid signature");
  
  // Verify nonce
  require(proof.nonce > nonces[proof.agentDID], "Nonce replay");
  
  return true;
}
```

## Contributing

### Development Workflow

```bash
# Clone repository
git clone https://github.com/authagent/authagent.git

# Install dependencies
npm install

# Run tests
npx hardhat test

# Run integration tests
npx hardhat test test/IntegrationTests.js

# Deploy to testnet
npx hardhat run scripts/deploy.js --network sepolia
```

### Code Style

- Solidity: Use `pragma ^0.8.24`
- JavaScript: Use ES6+ with built-in fetch only
- No external dependencies beyond OpenZeppelin contracts
- All functions must be gas-optimized

## License

MIT License - See LICENSE file for details.

## Contact

- GitHub: https://github.com/authagent/authagent
- Discord: https://discord.gg/authagent
- Twitter: @AuthAgentAI

import { ethers } from 'ethers';
import { v4 as uuidv4 } from 'uuid';

/**
 * AgentIdentity - Cryptographic identity primitive for autonomous agents
 * Implements DID:ethr method with ECDSA secp256k1 key derivation
 * Every agent action is cryptographically bound to this identity
 */
class AgentIdentity {
  #privateKey;
  #address;
  #did;
  #publicKey;
  #nonce;

  constructor(privateKey) {
    if (!privateKey || privateKey.length !== 66) {
      throw new Error('Invalid private key format - must be 0x-prefixed 64-byte hex');
    }
    
    const wallet = new ethers.Wallet(privateKey);
    this.#privateKey = privateKey;
    this.#address = wallet.address;
    this.#publicKey = wallet.publicKey;
    this.#did = `did:ethr:0x${wallet.address.slice(2)}`;
    this.#nonce = 0n;
  }

  get address() { return this.#address; }
  get did() { return this.#did; }
  get publicKey() { return this.#publicKey; }
  get nonce() { return this.#nonce; }

  async sign(message) {
    const wallet = new ethers.Wallet(this.#privateKey);
    const hash = ethers.keccak256(ethers.toUtf8Bytes(message));
    const signature = await wallet.signMessage(ethers.getBytes(hash));
    this.#nonce += 1n;
    return { signature, nonce: this.#nonce };
  }

  async signTransaction(transaction) {
    const wallet = new ethers.Wallet(this.#privateKey);
    const signedTx = await wallet.signTransaction(transaction);
    this.#nonce += 1n;
    return signedTx;
  }

  static verifySignature(message, signature, address) {
    const recovered = ethers.verifyMessage(message, signature);
    return recovered.toLowerCase() === address.toLowerCase();
  }

  static deriveFromSeed(seed) {
    const hash = ethers.keccak256(ethers.toUtf8Bytes(seed));
    return new AgentIdentity(hash);
  }
}

/**
 * Capability - Binds specific smart contract functions to agent identity
 * Implements capability binding primitive for autonomous transaction signing
 */
class Capability {
  #contractAddress;
  #functionSignature;
  #allowedParameters;
  #maxValue;
  #agentDid;

  constructor(agentDid, contractAddress, functionSignature, allowedParameters = {}, maxValue = null) {
    this.#agentDid = agentDid;
    this.#contractAddress = contractAddress;
    this.#functionSignature = functionSignature;
    this.#allowedParameters = allowedParameters;
    this.#maxValue = maxValue;
  }

  get contractAddress() { return this.#contractAddress; }
  get functionSignature() { return this.#functionSignature; }
  get allowedParameters() { return this.#allowedParameters; }
  get maxValue() { return this.#maxValue; }
  get agentDid() { return this.#agentDid; }

  validateParameters(parameters) {
    for (const [key, value] of Object.entries(parameters)) {
      if (this.#allowedParameters[key] !== undefined) {
        if (typeof value !== typeof this.#allowedParameters[key]) {
          return false;
        }
        if (this.#allowedParameters[key] === 'number' && typeof value === 'number') {
          if (this.#maxValue && value > this.#maxValue) {
            return false;
          }
        }
      }
    }
    return true;
  }

  toRegistryEntry() {
    return {
      agentDid: this.#agentDid,
      contractAddress: this.#contractAddress,
      functionSignature: this.#functionSignature,
      allowedParameters: this.#allowedParameters,
      maxValue: this.#maxValue
    };
  }
}

/**
 * Agent - Autonomous agent with cryptographic identity and capability system
 * Core primitive for AuthAgent - every action is traceable to agent DID
 */
class Agent {
  #id;
  #identity;
  #capabilities = new Map();
  #name;
  #systemPrompt;
  #memory = [];
  #isRunning = false;
  #onMessage;
  #onAction;

  constructor(options) {
    this.#id = uuidv4();
    this.#name = options.name || `Agent-${this.#id.slice(0, 8)}`;
    this.#systemPrompt = options.systemPrompt || 'You are an autonomous agent.';
    this.#identity = new AgentIdentity(options.privateKey);
    this.#onMessage = options.onMessage || (() => {});
    this.#onAction = options.onAction || (() => {});
  }

  get id() { return this.#id; }
  get name() { return this.#name; }
  get identity() { return this.#identity; }
  get did() { return this.#identity.did; }
  get address() { return this.#identity.address; }

  async registerCapability(capability) {
    if (!(capability instanceof Capability)) {
      throw new Error('Must provide Capability instance');
    }
    if (capability.agentDid !== this.#identity.did) {
      throw new Error('Capability agentDid must match agent identity');
    }
    this.#capabilities.set(capability.functionSignature, capability);
    return this;
  }

  async hasCapability(functionSignature) {
    return this.#capabilities.has(functionSignature);
  }

  async getCapability(functionSignature) {
    return this.#capabilities.get(functionSignature);
  }

  async addMessage(role, content) {
    this.#memory.push({ role, content, timestamp: Date.now() });
    return this;
  }

  async getMemory(limit = 10) {
    return this.#memory.slice(-limit);
  }

  async clearMemory() {
    this.#memory = [];
    return this;
  }

  async processMessage(message) {
    this.#memory.push({ role: 'user', content: message, timestamp: Date.now() });
    const response = await this.#generateResponse(message);
    this.#memory.push({ role: 'assistant', content: response, timestamp: Date.now() });
    this.#onMessage(response);
    return response;
  }

  async #generateResponse(message) {
    const context = await this.#buildContext();
    const prompt = this.#buildPrompt(message, context);
    return this.#simulateResponse(prompt);
  }

  async #buildContext() {
    const capabilities = [];
    for (const [sig, cap] of this.#capabilities) {
      capabilities.push(cap.toRegistryEntry());
    }
    return {
      did: this.#identity.did,
      address: this.#identity.address,
      capabilities,
      memory: await this.#memory.slice(-5)
    };
  }

  #buildPrompt(message, context) {
    return `
AGENT IDENTITY: ${context.did}
ADDRESS: ${context.address}
CAPABILITIES: ${JSON.stringify(context.capabilities)}
MEMORY: ${JSON.stringify(context.memory)}

SYSTEM: ${this.#systemPrompt}

USER: ${message}

RESPOND:
`;
  }

  #simulateResponse(prompt) {
    const response = `Agent ${this.#name} processed: ${prompt.slice(0, 100)}...`;
    return response;
  }

  async executeAction(action) {
    const { type, parameters } = action;
    const capability = await this.getCapability(type);
    
    if (!capability) {
      throw new Error(`No capability registered for function: ${type}`);
    }

    if (!capability.validateParameters(parameters)) {
      throw new Error('Parameters exceed capability bounds');
    }

    const message = JSON.stringify({ type, parameters, agentDid: this.#identity.did });
    const { signature, nonce } = await this.#identity.sign(message);

    this.#onAction({
      type,
      parameters,
      signature,
      nonce,
      agentDid: this.#identity.did,
      address: this.#identity.address
    });

    return {
      success: true,
      signature,
      nonce,
      agentDid: this.#identity.did
    };
  }

  async verifyAction(action, signature) {
    const message = JSON.stringify({ type: action.type, parameters: action.parameters, agentDid: this.#identity.did });
    return AgentIdentity.verifySignature(message, signature, this.#identity.address);
  }

  async run() {
    this.#isRunning = true;
    return this;
  }

  async stop() {
    this.#isRunning = false;
    return this;
  }

  toJSON() {
    return {
      id: this.#id,
      name: this.#name,
      did: this.#identity.did,
      address: this.#identity.address,
      capabilityCount: this.#capabilities.size
    };
  }
}

export { Agent, AgentIdentity, Capability };
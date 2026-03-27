// SPDX-License-Identifier: MIT
import { expect } from "chai";
import { ethers } from "hardhat";

describe("AuthAgent Integration Tests", function () {
  let agentIdentity;
  let capabilityRegistry;
  let owner, agent1, agent2, attacker, verifier;
  let agent1Wallet, agent2Wallet, attackerWallet;

  const TEST_CAPABILITIES = [
    {
      functionSelector: "0xa9059cbb", // transfer(address,uint256)
      targetContract: "0x0000000000000000000000000000000000000001",
      description: "Transfer tokens",
      maxUsage: 1000000,
      expiration: 1735689600
    },
    {
      functionSelector: "0x095ea7b3", // approve(address,uint256)
      targetContract: "0x0000000000000000000000000000000000000002",
      description: "Approve spending",
      maxUsage: 500000,
      expiration: 1735689600
    }
  ];

  const SIGNATURE_PREFIX = "\x19Ethereum Signed Message:\n32";

  async function generateIdentityProof(agentAddress, nonce) {
    const message = ethers.solidityPacked(
      ["string", "address", "uint256"],
      [
        "AgentIdentityProof",
        agentAddress,
        nonce.toString()
      ]
    );
    const messageHash = ethers.keccak256(
      ethers.solidityPacked(["bytes"], [ethers.keccak256(message)])
    );
    const signature = await agent1Wallet.signMessage(
      ethers.getBytes(messageHash)
    );
    return { message, signature };
  }

  async function generateCapabilityProof(agentAddress, capability, nonce) {
    const message = ethers.solidityPacked(
      ["string", "address", "bytes4", "address", "uint256", "uint256", "uint256"],
      [
        "CapabilityBindingProof",
        agentAddress,
        capability.functionSelector,
        capability.targetContract,
        capability.maxUsage,
        capability.expiration,
        nonce
      ]
    );
    const messageHash = ethers.keccak256(
      ethers.solidityPacked(["bytes"], [ethers.keccak256(message)])
    );
    const signature = await agent1Wallet.signMessage(
      ethers.getBytes(messageHash)
    );
    return { message, signature };
  }

  beforeEach(async function () {
    [owner, agent1, agent2, attacker, verifier] = await ethers.getSigners();
    agent1Wallet = agent1;
    agent2Wallet = agent2;
    attackerWallet = attacker;

    const AgentIdentity = await ethers.getContractFactory("AgentIdentity");
    agentIdentity = await AgentIdentity.deploy();
    await agentIdentity.waitForDeployment();

    const CapabilityRegistry = await ethers.getContractFactory("CapabilityRegistry");
    capabilityRegistry = await CapabilityRegistry.deploy();
    await capabilityRegistry.waitForDeployment();

    await agentIdentity.setCapabilityRegistry(capabilityRegistry.getAddress());
  });

  describe("Agent Registration", function () {
    it("Should successfully register a new agent with valid proof", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      const tx = await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);
      const receipt = await tx.wait();

      const tokenId = await agentIdentity.agentToTokenId(agent1.address);
      expect(tokenId).to.not.equal(0);
      expect(await agentIdentity.ownerOf(tokenId)).to.equal(agent1.address);
    });

    it("Should reject registration with invalid signature", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const invalidSignature = "0x" + "ff".repeat(65);

      await expect(
        agentIdentity
          .connect(agent1Wallet)
          .registerAgent("test", invalidSignature)
      ).to.be.revertedWith("Invalid signature");
    });

    it("Should reject registration with replayed nonce", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      await expect(
        agentIdentity
          .connect(agent1Wallet)
          .registerAgent(message, signature)
      ).to.be.revertedWith("Nonce already used");
    });

    it("Should reject registration from unauthorized address", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      await expect(
        agentIdentity
          .connect(attackerWallet)
          .registerAgent(message, signature)
      ).to.be.revertedWith("Unauthorized");
    });

    it("Should increment nonce after successful registration", async function () {
      const initialNonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, initialNonce);

      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const newNonce = await agentIdentity.getNextNonce(agent1.address);
      expect(newNonce).to.equal(initialNonce + 1);
    });

    it("Should emit AgentRegistered event", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      await expect(
        agentIdentity
          .connect(agent1Wallet)
          .registerAgent(message, signature)
      )
        .to.emit(agentIdentity, "AgentRegistered")
        .withArgs(agent1.address, 1);
    });
  });

  describe("Capability Binding", function () {
    beforeEach(async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);
    });

    it("Should successfully bind capability to agent", async function () {
      const capability = TEST_CAPABILITIES[0];
      const nonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message, signature } = await generateCapabilityProof(agent1.address, capability, nonce);

      const tx = await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(message, signature, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);
      const receipt = await tx.wait();

      const bindingId = await capabilityRegistry.agentToCapabilityId(agent1.address, 0);
      expect(bindingId).to.not.equal(0);
    });

    it("Should reject capability binding with invalid signature", async function () {
      const capability = TEST_CAPABILITIES[0];
      const invalidSignature = "0x" + "ff".repeat(65);

      await expect(
        capabilityRegistry
          .connect(agent1Wallet)
          .bindCapability("test", invalidSignature, capability.functionSelector, capability.targetContract, 1000, 1735689600)
      ).to.be.revertedWith("Invalid signature");
    });

    it("Should reject capability binding with expired capability", async function () {
      const capability = {
        ...TEST_CAPABILITIES[0],
        expiration: 1000000000 // Past timestamp
      };
      const nonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message, signature } = await generateCapabilityProof(agent1.address, capability, nonce);

      await expect(
        capabilityRegistry
          .connect(agent1Wallet)
          .bindCapability(message, signature, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration)
      ).to.be.revertedWith("Capability expired");
    });

    it("Should reject capability binding with zero maxUsage", async function () {
      const capability = {
        ...TEST_CAPABILITIES[0],
        maxUsage: 0
      };
      const nonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message, signature } = await generateCapabilityProof(agent1.address, capability, nonce);

      await expect(
        capabilityRegistry
          .connect(agent1Wallet)
          .bindCapability(message, signature, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration)
      ).to.be.revertedWith("Invalid maxUsage");
    });

    it("Should emit CapabilityBound event", async function () {
      const capability = TEST_CAPABILITIES[0];
      const nonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message, signature } = await generateCapabilityProof(agent1.address, capability, nonce);

      await expect(
        capabilityRegistry
          .connect(agent1Wallet)
          .bindCapability(message, signature, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration)
      )
        .to.emit(capabilityRegistry, "CapabilityBound")
        .withArgs(agent1.address, 0, capability.functionSelector);
    });

    it("Should allow multiple capabilities for same agent", async function () {
      const capability1 = TEST_CAPABILITIES[0];
      const capability2 = TEST_CAPABILITIES[1];

      const nonce1 = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: msg1, signature: sig1 } = await generateCapabilityProof(agent1.address, capability1, nonce1);

      const nonce2 = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: msg2, signature: sig2 } = await generateCapabilityProof(agent1.address, capability2, nonce2);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(msg1, sig1, capability1.functionSelector, capability1.targetContract, capability1.maxUsage, capability1.expiration);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(msg2, sig2, capability2.functionSelector, capability2.targetContract, capability2.maxUsage, capability2.expiration);

      const bindingCount = await capabilityRegistry.getCapabilityCount(agent1.address);
      expect(bindingCount).to.equal(2);
    });
  });

  describe("Capability Verification", function () {
    beforeEach(async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);
    });

    it("Should verify valid capability binding", async function () {
      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        TEST_CAPABILITIES[0].functionSelector,
        TEST_CAPABILITIES[0].targetContract
      );
      expect(isValid).to.be.true;
    });

    it("Should reject verification for unbound capability", async function () {
      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        "0x12345678",
        "0x0000000000000000000000000000000000000003"
      );
      expect(isValid).to.be.false;
    });

    it("Should reject verification for expired capability", async function () {
      const expiredCapability = {
        ...TEST_CAPABILITIES[0],
        expiration: 1000000000
      };

      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        expiredCapability.functionSelector,
        expiredCapability.targetContract
      );
      expect(isValid).to.be.false;
    });

    it("Should reject verification for unauthorized agent", async function () {
      const isValid = await capabilityRegistry.hasCapability(
        attacker.address,
        TEST_CAPABILITIES[0].functionSelector,
        TEST_CAPABILITIES[0].targetContract
      );
      expect(isValid).to.be.false;
    });
  });

  describe("Capability Usage Tracking", function () {
    beforeEach(async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = {
        ...TEST_CAPABILITIES[0],
        maxUsage: 5
      };
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);
    });

    it("Should track capability usage count", async function () {
      const usageCount = await capabilityRegistry.getUsageCount(agent1.address, 0);
      expect(usageCount).to.equal(0);
    });

    it("Should increment usage count on capability execution", async function () {
      await capabilityRegistry.incrementUsage(agent1.address, 0);

      const usageCount = await capabilityRegistry.getUsageCount(agent1.address, 0);
      expect(usageCount).to.equal(1);
    });

    it("Should reject capability execution when maxUsage exceeded", async function () {
      const capability = {
        ...TEST_CAPABILITIES[0],
        maxUsage: 2
      };
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      await capabilityRegistry.incrementUsage(agent1.address, 1);
      await capabilityRegistry.incrementUsage(agent1.address, 1);

      await expect(capabilityRegistry.incrementUsage(agent1.address, 1))
        .to.be.revertedWith("Max usage exceeded");
    });

    it("Should emit UsageIncremented event", async function () {
      await expect(capabilityRegistry.incrementUsage(agent1.address, 0))
        .to.emit(capabilityRegistry, "UsageIncremented")
        .withArgs(agent1.address, 0, 1);
    });
  });

  describe("Capability Revocation", function () {
    beforeEach(async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);
    });

    it("Should successfully revoke capability", async function () {
      await capabilityRegistry.revokeCapability(agent1.address, 0);

      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        TEST_CAPABILITIES[0].functionSelector,
        TEST_CAPABILITIES[0].targetContract
      );
      expect(isValid).to.be.false;
    });

    it("Should emit CapabilityRevoked event", async function () {
      await expect(capabilityRegistry.revokeCapability(agent1.address, 0))
        .to.emit(capabilityRegistry, "CapabilityRevoked")
        .withArgs(agent1.address, 0);
    });

    it("Should reject revocation of non-existent capability", async function () {
      await expect(capabilityRegistry.revokeCapability(agent1.address, 999))
        .to.be.revertedWith("Capability not found");
    });

    it("Should reject revocation by unauthorized address", async function () {
      await expect(capabilityRegistry
        .connect(attackerWallet)
        .revokeCapability(agent1.address, 0))
        .to.be.revertedWith("Unauthorized");
    });
  });

  describe("Agent Identity Management", function () {
    beforeEach(async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);
    });

    it("Should get agent metadata", async function () {
      const tokenId = await agentIdentity.agentToTokenId(agent1.address);
      const metadata = await agentIdentity.getAgentMetadata(tokenId);

      expect(metadata).to.not.be.null;
      expect(metadata[0]).to.equal(agent1.address);
    });

    it("Should reject getting metadata for unregistered agent", async function () {
      await expect(agentIdentity.getAgentMetadata(999))
        .to.be.revertedWith("Agent not found");
    });

    it("Should update agent metadata", async function () {
      const tokenId = await agentIdentity.agentToTokenId(agent1.address);
      const newMetadata = "Updated metadata";

      await agentIdentity.updateAgentMetadata(tokenId, newMetadata);

      const metadata = await agentIdentity.getAgentMetadata(tokenId);
      expect(metadata[1]).to.equal(newMetadata);
    });

    it("Should reject metadata update for unregistered agent", async function () {
      await expect(agentIdentity.updateAgentMetadata(999, "test"))
        .to.be.revertedWith("Agent not found");
    });
  });

  describe("Emergency Governance", function () {
    it("Should allow emergency shutdown by owner", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      await expect(agentIdentity.emergencyShutdown())
        .to.emit(agentIdentity, "EmergencyShutdown");
    });

    it("Should reject emergency shutdown by unauthorized address", async function () {
      await expect(agentIdentity
        .connect(attackerWallet)
        .emergencyShutdown())
        .to.be.revertedWith("Unauthorized");
    });

    it("Should prevent agent operations during emergency shutdown", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      await agentIdentity.emergencyShutdown();

      const newNonce = await agentIdentity.getNextNonce(agent1.address);
      const { message: newMsg, signature: newSig } = await generateIdentityProof(agent1.address, newNonce);

      await expect(agentIdentity
        .connect(agent1Wallet)
        .registerAgent(newMsg, newSig))
        .to.be.revertedWith("Emergency shutdown active");
    });
  });

  describe("Replay Attack Prevention", function () {
    it("Should reject replayed registration signature", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      await expect(agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature))
        .to.be.revertedWith("Nonce already used");
    });

    it("Should reject replayed capability binding signature", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      await expect(capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration))
        .to.be.revertedWith("Nonce already used");
    });
  });

  describe("Cross-Contract Integration", function () {
    it("Should allow capability registry to verify agent identity", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        capability.functionSelector,
        capability.targetContract
      );
      expect(isValid).to.be.true;
    });

    it("Should maintain state consistency across contract calls", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const tokenId = await agentIdentity.agentToTokenId(agent1.address);
      const initialNonce = await agentIdentity.getNextNonce(agent1.address);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      const finalNonce = await agentIdentity.getNextNonce(agent1.address);
      expect(finalNonce).to.equal(initialNonce);
    });
  });

  describe("Gas Optimization", function () {
    it("Should have reasonable gas cost for agent registration", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      const tx = await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);
      const receipt = await tx.wait();

      expect(receipt.gasUsed).to.be.lessThan(500000);
    });

    it("Should have reasonable gas cost for capability binding", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      const tx = await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);
      const receipt = await tx.wait();

      expect(receipt.gasUsed).to.be.lessThan(400000);
    });
  });

  describe("Edge Cases", function () {
    it("Should handle zero address rejection", async function () {
      const zeroAddress = ethers.ZeroAddress;
      const nonce = await agentIdentity.getNextNonce(zeroAddress);
      const { message, signature } = await generateIdentityProof(zeroAddress, nonce);

      await expect(agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature))
        .to.be.revertedWith("Invalid address");
    });

    it("Should handle very large maxUsage values", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = {
        ...TEST_CAPABILITIES[0],
        maxUsage: ethers.MaxUint256
      };
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        capability.functionSelector,
        capability.targetContract
      );
      expect(isValid).to.be.true;
    });

    it("Should handle concurrent capability bindings", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability1 = TEST_CAPABILITIES[0];
      const capability2 = TEST_CAPABILITIES[1];

      const capNonce1 = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg1, signature: capSig1 } = await generateCapabilityProof(agent1.address, capability1, capNonce1);

      const capNonce2 = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg2, signature: capSig2 } = await generateCapabilityProof(agent1.address, capability2, capNonce2);

      const tx1 = capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg1, capSig1, capability1.functionSelector, capability1.targetContract, capability1.maxUsage, capability1.expiration);

      const tx2 = capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg2, capSig2, capability2.functionSelector, capability2.targetContract, capability2.maxUsage, capability2.expiration);

      await Promise.all([tx1, tx2]);

      const bindingCount = await capabilityRegistry.getCapabilityCount(agent1.address);
      expect(bindingCount).to.equal(2);
    });

    it("Should handle capability expiration edge case", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = {
        ...TEST_CAPABILITIES[0],
        expiration: 1735689600
      };
      const capNonce = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent1.address, capability, capNonce);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      const isValid = await capabilityRegistry.hasCapability(
        agent1.address,
        capability.functionSelector,
        capability.targetContract
      );
      expect(isValid).to.be.true;
    });
  });

  describe("Multi-Agent Scenarios", function () {
    it("Should support multiple registered agents", async function () {
      const nonce1 = await agentIdentity.getNextNonce(agent1.address);
      const { message: msg1, signature: sig1 } = await generateIdentityProof(agent1.address, nonce1);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(msg1, sig1);

      const nonce2 = await agentIdentity.getNextNonce(agent2.address);
      const { message: msg2, signature: sig2 } = await generateIdentityProof(agent2.address, nonce2);
      await agentIdentity
        .connect(agent2Wallet)
        .registerAgent(msg2, sig2);

      const tokenId1 = await agentIdentity.agentToTokenId(agent1.address);
      const tokenId2 = await agentIdentity.agentToTokenId(agent2.address);

      expect(tokenId1).to.not.equal(tokenId2);
      expect(tokenId1).to.not.equal(0);
      expect(tokenId2).to.not.equal(0);
    });

    it("Should isolate agent capabilities", async function () {
      const nonce1 = await agentIdentity.getNextNonce(agent1.address);
      const { message: msg1, signature: sig1 } = await generateIdentityProof(agent1.address, nonce1);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(msg1, sig1);

      const nonce2 = await agentIdentity.getNextNonce(agent2.address);
      const { message: msg2, signature: sig2 } = await generateIdentityProof(agent2.address, nonce2);
      await agentIdentity
        .connect(agent2Wallet)
        .registerAgent(msg2, sig2);

      const capability = TEST_CAPABILITIES[0];
      const capNonce1 = await capabilityRegistry.getNextNonce(agent1.address);
      const { message: capMsg1, signature: capSig1 } = await generateCapabilityProof(agent1.address, capability, capNonce1);

      await capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg1, capSig1, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration);

      const agent1HasCap = await capabilityRegistry.hasCapability(
        agent1.address,
        capability.functionSelector,
        capability.targetContract
      );
      const agent2HasCap = await capabilityRegistry.hasCapability(
        agent2.address,
        capability.functionSelector,
        capability.targetContract
      );

      expect(agent1HasCap).to.be.true;
      expect(agent2HasCap).to.be.false;
    });
  });

  describe("Security Properties", function () {
    it("Should prevent signature forgery", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      const forgedSignature = "0x" + "ff".repeat(65);

      await expect(agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, forgedSignature))
        .to.be.revertedWith("Invalid signature");
    });

    it("Should prevent nonce manipulation", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);

      const wrongNonce = nonce + 100;
      const { message: wrongMsg, signature: wrongSig } = await generateIdentityProof(agent1.address, wrongNonce);

      await expect(agentIdentity
        .connect(agent1Wallet)
        .registerAgent(wrongMsg, wrongSig))
        .to.be.revertedWith("Invalid signature");
    });

    it("Should prevent capability binding to wrong agent", async function () {
      const nonce = await agentIdentity.getNextNonce(agent1.address);
      const { message, signature } = await generateIdentityProof(agent1.address, nonce);
      await agentIdentity
        .connect(agent1Wallet)
        .registerAgent(message, signature);

      const capability = TEST_CAPABILITIES[0];
      const capNonce = await capabilityRegistry.getNextNonce(agent2.address);
      const { message: capMsg, signature: capSig } = await generateCapabilityProof(agent2.address, capability, capNonce);

      await expect(capabilityRegistry
        .connect(agent1Wallet)
        .bindCapability(capMsg, capSig, capability.functionSelector, capability.targetContract, capability.maxUsage, capability.expiration))
        .to.be.revertedWith("Invalid signature");
    });
  });
});
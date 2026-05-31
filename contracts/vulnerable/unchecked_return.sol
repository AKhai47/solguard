// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABILITY: Unchecked Return Value from .send() / Low-Level Calls
//
// WHAT IT IS:
//   Solidity provides three ways to send ETH to an address:
//     • address.transfer(amount)  — reverts on failure, 2300 gas stipend
//     • address.send(amount)      — returns bool, 2300 gas stipend, does NOT revert
//     • address.call{value}("")   — returns (bool, bytes), forwards all gas, does NOT revert
//
//   .send() and .call() return a bool indicating success or failure. If the
//   return value is ignored and the transfer silently fails (e.g., the
//   recipient is a contract with a reverting fallback, or gas is insufficient),
//   the contract continues executing as if the transfer succeeded. State
//   changes that happened before the send (e.g., balance zeroing) are
//   committed, and the ETH stays locked in the contract forever with no
//   recovery mechanism.
//
// HOW IT IS EXPLOITED / HOW FUNDS ARE LOCKED:
//   Scenario A — accidental lock:
//     1. A multisig or proxy contract with a reverting fallback calls
//        withdraw() on this vault.
//     2. The .send() returns false because the recipient's receive() reverts.
//     3. The vault has already zeroed balances[msg.sender] before the send,
//        so the user can never retry. Their funds are permanently locked.
//
//   Scenario B — griefing by a malicious recipient:
//     1. An attacker participates as a recipient in a multi-payout contract.
//     2. They deploy a contract that conditionally reverts its fallback based
//        on a flag (open during deposit, closed during withdrawal).
//     3. The vault's loop silently skips their payout, logs nothing, and
//        continues — their share is locked and the attacker can later claim
//        a refund by other means or simply grief the protocol.
//
//   Scenario C — pull-payment ignored:
//     The contract intends to use a pull-payment pattern but calls send()
//     without checking the return value in the push path, meaning individual
//     payouts can silently fail during batch operations.
//
// THE FIX:
//   Option A: Use .transfer() if 2300 gas is acceptable — it reverts on failure.
//   Option B: Always check the return value of .send():
//               bool success = payable(msg.sender).send(amount);
//               require(success, "ETH send failed");
//   Option C: Use .call{value: amount}("") and check the bool return:
//               (bool ok, ) = payable(msg.sender).call{value: amount}("");
//               require(ok, "ETH transfer failed");
//   Option D: Implement the pull-payment (withdrawal) pattern so recipients
//             initiate their own withdrawals, isolating failures per user.
// =============================================================================

contract UncheckedSendVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: .send() return value is discarded.
    // If the send fails, balances[msg.sender] is still zeroed — ETH is locked.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        balances[msg.sender] = 0; // state updated...

        // !! Return value ignored — failure is silent !!
        payable(msg.sender).send(amount);
        // If the above fails: balance is 0, ETH never left, funds are gone.
    }

    // VULNERABLE: batch payout loop — any individual failure is silently skipped.
    function distributePayout(address[] calldata recipients, uint256 share) external {
        require(msg.sender == owner, "Not owner");
        for (uint256 i = 0; i < recipients.length; i++) {
            // !! If recipient[i] is a contract that reverts, this silently skips it !!
            payable(recipients[i]).send(share); // return value thrown away
        }
    }

    // VULNERABLE: owner drain uses low-level call but ignores result.
    function emergencyDrain() external {
        require(msg.sender == owner, "Not owner");
        // !! .call return value not captured !!
        owner.call{value: address(this).balance}(""); // solhint-disable-line
    }

    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

// CONTRACT that causes silent failures — shows how a recipient can cause
// the send() to fail without the vault detecting it.
contract RevertingRecipient {
    bool public acceptPayments = true;

    // Toggling this off makes any .send() or .transfer() to this contract fail.
    function setAcceptPayments(bool accept) external {
        acceptPayments = accept;
    }

    receive() external payable {
        require(acceptPayments, "Not accepting ETH right now");
    }
}

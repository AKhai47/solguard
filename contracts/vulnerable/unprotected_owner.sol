// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABILITY: Missing Access Control (Unprotected Critical Functions)
//
// WHAT IT IS:
//   Critical administrative functions — transferOwnership(), destroy(),
//   setFeeRate(), pause() — have no access control whatsoever. There is no
//   onlyOwner modifier, no role-based check, and no require(msg.sender == owner).
//   Any externally-owned account or contract can call them freely.
//
// HOW IT IS EXPLOITED:
//   Attack is trivial and requires no setup:
//
//   1. OWNERSHIP TAKEOVER:
//      An attacker calls transferOwnership(attacker_address) directly.
//      They are now the owner and can call any owner-gated business logic.
//
//   2. SELF-DESTRUCT / FUND DRAIN:
//      The attacker calls destroy() passing their own address.
//      selfdestruct() sends the entire contract balance to that address
//      and marks the contract as destroyed. All state is wiped; any future
//      calls to the contract become no-ops. Funds held for legitimate users
//      are irrecoverably stolen.
//
//   3. FEE MANIPULATION:
//      An attacker calls setFeeRate(10000) to set fees to 100%, extracting
//      all value from every future transaction, or setFeeRate(0) to drain
//      protocol revenue.
//
//   4. PAUSE GRIEFING:
//      An attacker calls setPaused(true) to halt all deposits and withdrawals,
//      holding user funds hostage.
//
//   Real-world example: Parity Multisig wallet bug (July 2017) — an unprotected
//   initWallet() function allowed anyone to re-initialize the contract and
//   become owner, leading to $30 million stolen. A follow-up bug in November
//   2017 caused $150 million to be permanently frozen.
//
// THE FIX:
//   1. Add an onlyOwner modifier and apply it to every privileged function.
//   2. Set owner = msg.sender in the constructor so ownership is established
//      at deploy time.
//   3. For complex role requirements, use OpenZeppelin's Ownable or
//      AccessControl contracts rather than rolling your own.
//   4. Consider a two-step ownership transfer (propose + accept) to prevent
//      accidentally transferring ownership to an uncontrolled address.
//   5. Emit events on all ownership/config changes for off-chain monitoring.
// =============================================================================

contract UnprotectedVault {
    address public owner;
    uint256 public feeRate; // basis points (100 = 1%)
    bool public paused;

    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        feeRate = 50; // 0.5% default
    }

    // !! NO ACCESS CONTROL — anyone can become owner !!
    function transferOwnership(address newOwner) external {
        owner = newOwner; // missing: require(msg.sender == owner)
    }

    // !! NO ACCESS CONTROL — anyone can destroy the contract and steal all ETH !!
    function destroy(address payable recipient) external {
        selfdestruct(recipient); // missing: require(msg.sender == owner)
    }

    // !! NO ACCESS CONTROL — anyone can set fees to anything !!
    function setFeeRate(uint256 newRate) external {
        require(newRate <= 10000, "Max 100%");
        feeRate = newRate; // missing: require(msg.sender == owner)
    }

    // !! NO ACCESS CONTROL — anyone can pause/unpause the protocol !!
    function setPaused(bool _paused) external {
        paused = _paused; // missing: require(msg.sender == owner)
    }

    // !! NO ACCESS CONTROL — anyone can drain all collected fees !!
    function withdrawFees(address payable to) external {
        uint256 fees = address(this).balance - _totalUserBalances();
        (bool ok, ) = to.call{value: fees}("");
        require(ok, "Transfer failed");
        // missing: require(msg.sender == owner)
    }

    function deposit() external payable {
        require(!paused, "Paused");
        uint256 fee = (msg.value * feeRate) / 10000;
        balances[msg.sender] += msg.value - fee;
    }

    function withdraw() external {
        require(!paused, "Paused");
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        balances[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function _totalUserBalances() internal view returns (uint256 total) {
        // NOTE: in a real contract you would track this with a running sum.
        // Omitted here to keep the vulnerability illustration focused.
        return 0;
    }
}

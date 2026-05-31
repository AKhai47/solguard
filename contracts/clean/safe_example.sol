// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// =============================================================================
// SAFE EXAMPLE: Secure Withdrawal Contract
// =============================================================================
//
// This contract demonstrates how to correctly implement a withdrawal vault by
// addressing each of the five vulnerability classes shown in contracts/vulnerable/.
//
// SECURITY DECISIONS EXPLAINED INLINE (look for [SAFE] tags):
//
//   [SAFE-1] REENTRANCY  — checks-effects-interactions pattern + mutex guard
//   [SAFE-2] AUTH        — msg.sender (never tx.origin) for all access control
//   [SAFE-3] ARITHMETIC  — Solidity ^0.8.x built-in overflow/underflow protection
//   [SAFE-4] RETURN VAL  — .call() return value always checked with require()
//   [SAFE-5] ACCESS CTRL — onlyOwner modifier on every privileged function
// =============================================================================

contract SafeVault {
    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    address public owner;
    bool private _locked; // [SAFE-1] reentrancy mutex
    uint256 public feeRateBps; // fee in basis points (100 = 1%)
    bool public paused;

    mapping(address => uint256) public balances;
    uint256 public accumulatedFees;

    // -------------------------------------------------------------------------
    // Events — emit on every state-changing action for off-chain auditability
    // -------------------------------------------------------------------------

    event Deposited(address indexed user, uint256 amount, uint256 fee);
    event Withdrawn(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event FeeRateUpdated(uint256 oldRate, uint256 newRate);
    event FeesWithdrawn(address indexed to, uint256 amount);
    event Paused(bool isPaused);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    // [SAFE-5] Single, clearly named modifier applied to every admin function.
    // Uses msg.sender — NOT tx.origin — so contract intermediaries cannot
    // impersonate the owner. [SAFE-2]
    modifier onlyOwner() {
        require(msg.sender == owner, "SafeVault: caller is not owner");
        _;
    }

    // [SAFE-1] Reentrancy guard: sets _locked before the function body runs
    // and clears it after. Any reentrant call hits the require and reverts.
    modifier nonReentrant() {
        require(!_locked, "SafeVault: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    modifier whenNotPaused() {
        require(!paused, "SafeVault: contract is paused");
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor(uint256 initialFeeRateBps) {
        require(initialFeeRateBps <= 1000, "SafeVault: fee cannot exceed 10%");

        // [SAFE-2] Owner is set from msg.sender at deploy time — the deployer
        // explicitly becomes owner, no ambiguity about tx.origin vs msg.sender.
        owner = msg.sender;
        feeRateBps = initialFeeRateBps;

        emit OwnershipTransferred(address(0), msg.sender);
    }

    // -------------------------------------------------------------------------
    // User-facing functions
    // -------------------------------------------------------------------------

    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "SafeVault: deposit must be > 0");

        // [SAFE-3] Solidity 0.8.x arithmetic reverts on overflow automatically.
        // No SafeMath or manual guards needed for addition here.
        uint256 fee = (msg.value * feeRateBps) / 10000;
        uint256 credited = msg.value - fee;

        balances[msg.sender] += credited;
        accumulatedFees += fee;

        emit Deposited(msg.sender, credited, fee);
    }

    // [SAFE-1] Checks-Effects-Interactions pattern:
    //   CHECK:   require balance > 0
    //   EFFECT:  balances[msg.sender] = 0   (state updated BEFORE external call)
    //   INTERACT: msg.sender.call{value}    (external call happens last)
    //
    // Combined with nonReentrant, this is doubly protected: even if the
    // interaction somehow re-enters, the mutex reverts it immediately.
    function withdraw() external nonReentrant whenNotPaused {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "SafeVault: nothing to withdraw");

        // EFFECT first — state is consistent before any external call
        balances[msg.sender] = 0;

        // [SAFE-4] Always capture and check the return value of .call().
        // .transfer() would also work here (it reverts on failure), but
        // .call() is preferred post-EIP-1884 because .transfer() hard-codes
        // 2300 gas which can fail if the recipient has non-trivial receive() logic.
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "SafeVault: ETH transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    // -------------------------------------------------------------------------
    // Owner-only admin functions — all guarded by onlyOwner [SAFE-5]
    // -------------------------------------------------------------------------

    // Two-step ownership transfer: the new owner must accept explicitly,
    // preventing accidental transfer to an address no one controls.
    address public pendingOwner;

    function transferOwnership(address newOwner) external onlyOwner {
        // [SAFE-2] msg.sender checked by onlyOwner — no tx.origin anywhere
        require(newOwner != address(0), "SafeVault: zero address");
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        // [SAFE-2] The pending owner must actively call this — no phishing vector.
        require(msg.sender == pendingOwner, "SafeVault: not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function setFeeRate(uint256 newRateBps) external onlyOwner {
        require(newRateBps <= 1000, "SafeVault: fee cannot exceed 10%");
        emit FeeRateUpdated(feeRateBps, newRateBps);
        feeRateBps = newRateBps;
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
    }

    // [SAFE-4] Return value of .call() is checked.
    // [SAFE-5] onlyOwner prevents unauthorized fee extraction.
    function withdrawFees(address payable to) external onlyOwner nonReentrant {
        require(to != address(0), "SafeVault: zero address");
        uint256 amount = accumulatedFees;
        require(amount > 0, "SafeVault: no fees to withdraw");

        // EFFECT before INTERACT [SAFE-1]
        accumulatedFees = 0;

        (bool ok, ) = to.call{value: amount}("");
        require(ok, "SafeVault: fee transfer failed");

        emit FeesWithdrawn(to, amount);
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

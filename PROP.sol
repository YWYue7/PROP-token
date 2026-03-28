// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PROPToken
 * @notice A simplified ERC-20 security token representing fractional 
 * rental income rights of a Grade A London office asset.
 * Implements KYC whitelisting, burn-on-redemption, and dividend distribution.
 */
contract PROPToken {

    // ─────────────────────────────────────────
    // STATE VARIABLES
    // ─────────────────────────────────────────

    // Token metadata
    string public name = "PROP Token";
    string public symbol = "PROP";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    // Contract owner (issuer)
    address public owner;

    // Tracks token balance of each address
    mapping(address => uint256) public balanceOf;

    // Tracks how much one address has approved another to spend
    // allowance[owner][spender] = amount
    mapping(address => mapping(address => uint256)) public allowance;

    // KYC whitelist: only approved addresses can hold or transfer tokens
    mapping(address => bool) public isWhitelisted;

    // Dividend tracking
    // totalDividend: cumulative dividend per token unit added by owner
    // lastDividend: the cumulative total at the time each holder last claimed
    uint256 public totalDividend;
    mapping(address => uint256) public lastDividend;

    // ─────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────

    // Emitted on every token transfer (including mint and burn)
    event Transfer(address indexed from, address indexed to, uint256 value);

    // Emitted when a holder approves a spender
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // Emitted when an address is added to or removed from the whitelist
    event WhitelistUpdated(address indexed account, bool status);

    // Emitted when owner distributes a new dividend round
    event DividendDistributed(uint256 amount);

    // Emitted when a holder claims their dividend
    event DividendClaimed(address indexed holder, uint256 amount);

    // Emitted when tokens are burned on redemption
    event Burned(address indexed holder, uint256 amount);

    // ─────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────

    /**
     * @notice Runs once at deployment.
     * Mints 10,000,000 PROP to the deployer and whitelists them.
     */
    constructor() {
        owner = msg.sender;

        // Mint initial supply: 10,000,000 tokens with 18 decimal places
        uint256 initialSupply = 10_000_000 * (10 ** decimals);
        totalSupply = initialSupply;
        balanceOf[owner] = initialSupply;

        // Deployer is automatically KYC-approved
        isWhitelisted[owner] = true;

        // Minting is represented as a transfer from the zero address
        emit Transfer(address(0), owner, initialSupply);
    }

    // ─────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────

    /**
     * @notice Restricts function access to the contract owner only.
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /**
     * @notice Restricts function access to whitelisted addresses only.
     */
    modifier onlyWhitelisted(address _addr) {
        require(isWhitelisted[_addr], "Address not whitelisted");
        _;
    }

    // ─────────────────────────────────────────
    // WHITELIST MANAGEMENT
    // ─────────────────────────────────────────

    /**
     * @notice Adds or removes an address from the KYC whitelist.
     * @dev Only callable by the owner (issuer/compliance officer).
     * @param _addr The address to update.
     * @param _status True to whitelist, false to remove.
     */
    function setWhitelist(address _addr, bool _status) public onlyOwner {
        isWhitelisted[_addr] = _status;
        emit WhitelistUpdated(_addr, _status);
    }

    // ─────────────────────────────────────────
    // ERC-20 TRANSFER FUNCTIONS
    // ─────────────────────────────────────────

    /**
     * @notice Transfers tokens from caller to recipient.
     * @dev Both sender and recipient must be KYC-whitelisted.
     * This enforces the ERC-1400 compliance layer described in the paper.
     * @param _to Recipient address.
     * @param _amount Amount of tokens to transfer.
     */
    function transfer(address _to, uint256 _amount) public returns (bool) {
        require(isWhitelisted[msg.sender], "Sender not whitelisted");
        require(isWhitelisted[_to], "Recipient not whitelisted");
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");

        balanceOf[msg.sender] -= _amount;
        balanceOf[_to] += _amount;

        emit Transfer(msg.sender, _to, _amount);
        return true;
    }

    /**
     * @notice Approves a spender to transfer tokens on the caller's behalf.
     * @dev Required for Uniswap liquidity pool interactions.
     * @param _spender Address authorised to spend.
     * @param _amount Maximum amount the spender may transfer.
     */
    function approve(address _spender, uint256 _amount) public returns (bool) {
        allowance[msg.sender][_spender] = _amount;
        emit Approval(msg.sender, _spender, _amount);
        return true;
    }

    /**
     * @notice Transfers tokens on behalf of another address using an allowance.
     * @dev Used by Uniswap pools and other approved protocols.
     * Both from and to addresses must be whitelisted.
     * @param _from Address to transfer from.
     * @param _to Address to transfer to.
     * @param _amount Amount to transfer.
     */
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool) {
        require(isWhitelisted[_from], "Sender not whitelisted");
        require(isWhitelisted[_to], "Recipient not whitelisted");
        require(balanceOf[_from] >= _amount, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _amount, "Allowance exceeded");

        allowance[_from][msg.sender] -= _amount;
        balanceOf[_from] -= _amount;
        balanceOf[_to] += _amount;

        emit Transfer(_from, _to, _amount);
        return true;
    }

    // ─────────────────────────────────────────
    // BURN MECHANISM
    // ─────────────────────────────────────────

    /**
     * @notice Burns tokens on redemption at lock-up expiry.
     * @dev Reduces both the caller's balance and the total supply,
     * ensuring on-chain supply remains equivalent to the underlying asset scale.
     * Represents the burn-on-redemption mechanism described in Section 3.2.
     * @param _amount Number of tokens to burn.
     */
    function burn(uint256 _amount) public {
        require(isWhitelisted[msg.sender], "Not whitelisted");
        require(balanceOf[msg.sender] >= _amount, "Insufficient balance");

        balanceOf[msg.sender] -= _amount;
        totalSupply -= _amount;

        // Burn is represented as a transfer to the zero address
        emit Transfer(msg.sender, address(0), _amount);
        emit Burned(msg.sender, _amount);
    }

    // ─────────────────────────────────────────
    // DIVIDEND DISTRIBUTION
    // ─────────────────────────────────────────

    /**
     * @notice Called by the owner each quarter to record a new dividend round.
     * @dev Does not transfer funds directly. Records cumulative dividend total
     * so each holder can calculate their proportional share when they claim.
     * Simulates the quarterly USDC distribution described in Section 3.2.
     * @param _amount Total ETH amount being made available for this round.
     */
    function distributeDividend(uint256 _amount) public onlyOwner {
        require(totalSupply > 0, "No tokens in circulation");
        require(_amount > 0, "Amount must be greater than zero");

        totalDividend += _amount;
        emit DividendDistributed(_amount);
    }

    /**
     * @notice Allows a whitelisted holder to claim their accrued dividend.
     * @dev Dividend owed is calculated as:
     *      owed = (totalDividend - lastDividend[holder]) * balance / totalSupply
     * This ensures proportional distribution based on current holdings.
     */
    function claimDividend() public {
        require(isWhitelisted[msg.sender], "Not whitelisted");

        // Calculate proportional share of unclaimed dividends
        uint256 owed = (totalDividend - lastDividend[msg.sender])
                        * balanceOf[msg.sender]
                        / totalSupply;

        require(owed > 0, "Nothing to claim");

        // Update checkpoint before transfer to prevent re-entrancy
        lastDividend[msg.sender] = totalDividend;

        // Transfer ETH to holder
        (bool success, ) = payable(msg.sender).call{value: owed}("");
        require(success, "Transfer failed");

        emit DividendClaimed(msg.sender, owed);
    }

    // ─────────────────────────────────────────
    // FALLBACK
    // ─────────────────────────────────────────

    /**
     * @notice Allows the contract to receive ETH for the dividend pool.
     * @dev Owner sends ETH to this contract, then calls distributeDividend().
     */
    receive() external payable {}

}
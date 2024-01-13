pragma solidity 0.8.17;

contract Escrow {
    mapping(address => uint256) public balances;

    constructor() {}

    function tokenIn(address _depositor, uint256 _amount) external {
        balances[_depositor] = _amount;
    }

    function getBalance(address _depositor) external view returns (uint256) {
        return balances[_depositor];
    }
}
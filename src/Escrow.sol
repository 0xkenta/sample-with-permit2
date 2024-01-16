pragma solidity 0.8.17;

contract Escrow {
    mapping(address => mapping(address => uint256)) public balances;

    constructor() {}

    // caution: no access control because of the sample code!
    function tokenIn(address _depositor, address _token, uint256 _amount) external {
        balances[_depositor][_token] += _amount;
    }

    function getBalance(address _depositor, address _token) external view returns (uint256) {
        return balances[_depositor][_token];
    }
}

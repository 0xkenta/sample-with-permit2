pragma solidity 0.8.17;

interface IEscrow {
    function tokenIn(address _depositor, address _token, uint256 _amount) external;
}

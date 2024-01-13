pragma solidity 0.8.17;

interface IEscrow {
    function tokenIn(address _depositor, uint256 _amount) external;
}
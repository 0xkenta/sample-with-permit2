pragma solidity 0.8.17;

import {IEscrow} from "./interfaces/IEscrow.sol";
import {IPermit2} from "./interfaces/IPermit2.sol";

contract Verifier {
    IPermit2 public permit2;
    IEscrow public escrow;

    constructor(address _permit2, address _escrow) {
        permit2 = IPermit2(_permit2);
        escrow = IEscrow(_escrow);
    }

    function deposit(
        IPermit2.PermitTransferFrom memory _permit,
        IPermit2.SignatureTransferDetails calldata _transferDetails,
        address _from,
        bytes calldata _signature
    ) external {
        permit2.permitTransferFrom(_permit, _transferDetails, _from, _signature);
        escrow.tokenIn(_from, _transferDetails.requestedAmount);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {SafeERC20, IERC20, IERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {SignatureVerification} from "../src/libraries/SignatureVerification.sol";
import {TokenProvider} from "./utils/TokenProvider.sol";
import {PermitSignature} from "./utils/PermitSignature.sol";
import {AddressBuilder} from "./utils/AddressBuilder.sol";
import {AmountBuilder} from "./utils/AmountBuilder.sol";
import {StructBuilder} from "./utils/StructBuilder.sol";
import {Escrow} from "../src/Escrow.sol";
import {SignatureTransfer} from "../src/SignatureTransfer.sol";
import {Verifier} from "../src/Verifier.sol";
import {GasSnapshot} from "forge-gas-snapshot/GasSnapshot.sol";
import {IPermit2} from "../src/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "../src/interfaces/ISignatureTransfer.sol";
import {InvalidNonce, SignatureExpired} from "../src/PermitErrors.sol";

contract SignatureTransferTest is Test, PermitSignature, TokenProvider, GasSnapshot {
    using AddressBuilder for address[];
    using AmountBuilder for uint256[];

    event UnorderedNonceInvalidation(address indexed owner, uint256 word, uint256 mask);
    event Transfer(address indexed from, address indexed token, address indexed to, uint256 amount);

    struct MockWitness {
        uint256 value;
        address person;
        bool test;
    }

    string public constant _PERMIT_TRANSFER_TYPEHASH_STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";

    string public constant _PERMIT_BATCH_WITNESS_TRANSFER_TYPEHASH_STUB =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";

    string public constant _TOKEN_PERMISSIONS_TYPESTRING = "TokenPermissions(address token,uint256 amount)";

    string constant MOCK_WITNESS_TYPE = "MockWitness(uint256 value,address person,bool test)";

    string constant WITNESS_TYPE_STRING =
        "MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)";

    bytes32 constant FULL_EXAMPLE_WITNESS_TYPEHASH = keccak256(
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)"
    );

    bytes32 constant FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,MockWitness witness)MockWitness(uint256 value,address person,bool test)TokenPermissions(address token,uint256 amount)"
    );

    IPermit2 permit2;
    Escrow escrow;
    Verifier verifier;

    address from;
    uint256 fromPrivateKey;
    uint256 defaultAmount = 1 ** 18;

    address address0 = address(0x0);
    address address2 = address(0x2);

    bytes32 DOMAIN_SEPARATOR;

    function setUp() public {
        permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        escrow = new Escrow();
        verifier = new Verifier(address(permit2), address(escrow));

        fromPrivateKey = 0x12341234;
        from = vm.addr(fromPrivateKey);

        initializeERC20Tokens();

        setERC20TestTokens(from);
        setERC20TestTokenApprovals(vm, from, address(permit2));
    }

    function testCorrectWitnessTypehashes() public {
        assertEq(
            keccak256(abi.encodePacked(_PERMIT_TRANSFER_TYPEHASH_STUB, WITNESS_TYPE_STRING)),
            FULL_EXAMPLE_WITNESS_TYPEHASH
        );
        assertEq(
            keccak256(abi.encodePacked(_PERMIT_BATCH_WITNESS_TRANSFER_TYPEHASH_STUB, WITNESS_TYPE_STRING)),
            FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH
        );
    }

    function getTransferDetails(address to, uint256 amount)
        private
        pure
        returns (IPermit2.SignatureTransferDetails memory)
    {
        return IPermit2.SignatureTransferDetails({to: to, requestedAmount: amount});
    }

    function testPermitTransferFrom() public {
        uint256 nonce = 0;
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address(escrow));
        uint256 escrowBalanceBefore = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceBefore, 0);

        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), defaultAmount);

        verifier.deposit(permit, transferDetails, from, sig);

        assertEq(token0.balanceOf(from), startBalanceFrom - defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo + defaultAmount);

        uint256 escrowBalanceAfter = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceAfter, escrowBalanceBefore + defaultAmount);
    }

    function testPermitTransferFromCompactSig() public {
        uint256 nonce = 0;
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        bytes memory sig =
            getCompactPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));
        assertEq(sig.length, 64);

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address(escrow));

        uint256 escrowBalanceBefore = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceBefore, 0);

        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), defaultAmount);

        snapStart("permitTransferFromCompactSig");
        verifier.deposit(permit, transferDetails, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom - defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo + defaultAmount);

        uint256 escrowBalanceAfter = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceAfter, escrowBalanceBefore + defaultAmount);
    }

    function testPermitTransferFromIncorrectSigLength() public {
        uint256 nonce = 0;
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));
        bytes memory sigExtra = bytes.concat(sig, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), defaultAmount);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        verifier.deposit(permit, transferDetails, from, sigExtra);
    }

    // function testPermitTransferFromToSpender() public {
    //     uint256 nonce = 0;
    //     // signed spender is address(this)
    //     ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
    //     bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

    //     uint256 startBalanceFrom = token0.balanceOf(from);
    //     uint256 startBalanceTo = token0.balanceOf(address0);

    //     ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address0, defaultAmount);

    //     permit2.permitTransferFrom(permit, transferDetails, from, sig);

    //     assertEq(token0.balanceOf(from), startBalanceFrom - defaultAmount);
    //     assertEq(token0.balanceOf(address0), startBalanceTo + defaultAmount);
    // }

    function testPermitTransferFromInvalidNonce() public {
        uint256 nonce = 0;
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), defaultAmount);
        verifier.deposit(permit, transferDetails, from, sig);

        vm.expectRevert(InvalidNonce.selector);
        verifier.deposit(permit, transferDetails, from, sig);
    }

    function testPermitTransferFromRandomNonceAndAmount(uint256 nonce, uint128 amount) public {
        token0.mint(address(from), amount);
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        permit.permitted.amount = amount;
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address(escrow));

        uint256 escrowBalanceBefore = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceBefore, 0);

        IPermit2.SignatureTransferDetails memory transferDetails = getTransferDetails(address(escrow), amount);

        verifier.deposit(permit, transferDetails, from, sig);

        assertEq(token0.balanceOf(from), startBalanceFrom - amount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo + amount);

        uint256 escrowBalanceAfter = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceAfter, escrowBalanceBefore + amount);
    }

    function testPermitTransferSpendLessThanFull(uint256 nonce, uint128 amount) public {
        token0.mint(address(from), amount);
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        permit.permitted.amount = amount;
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address(escrow));

        uint256 escrowBalanceBefore = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceBefore, 0);

        uint256 amountToSpend = amount / 2;
        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), amountToSpend);
        verifier.deposit(permit, transferDetails, from, sig);

        assertEq(token0.balanceOf(from), startBalanceFrom - amountToSpend);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo + amountToSpend);

        uint256 escrowBalanceAfter = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceAfter, escrowBalanceBefore + amountToSpend);
    }

    // function testPermitBatchTransferFrom() public {
    //     uint256 nonce = 0;
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
    //     bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

    //     address[] memory to = AddressBuilder.fill(1, address(address2)).push(address(address0));
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);

    //     uint256 startBalanceFrom0 = token0.balanceOf(from);
    //     uint256 startBalanceFrom1 = token1.balanceOf(from);
    //     uint256 startBalanceTo0 = token0.balanceOf(address2);
    //     uint256 startBalanceTo1 = token1.balanceOf(address0);

    //     permit2.permitTransferFrom(permit, toAmountPairs, from, sig);

    //     assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
    //     assertEq(token1.balanceOf(from), startBalanceFrom1 - defaultAmount);
    //     assertEq(token0.balanceOf(address2), startBalanceTo0 + defaultAmount);
    //     assertEq(token1.balanceOf(address0), startBalanceTo1 + defaultAmount);
    // }

    function testPermitBatchMultiPermitSingleTransfer() public {
        uint256 nonce = 0;
        address escrowAddress = address(escrow);
        address token0Address = address(token0);
        address token1Address = address(token1);

        address[] memory tokens = AddressBuilder.fill(1, token0Address).push(token1Address);
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);

        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        // must fill address to even though token0 wont get sent.
        // transfer details must be lenght of permit
        address[] memory to = AddressBuilder.fill(1, escrowAddress).push(escrowAddress);
        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(defaultAmount, to);
        // spender doesnt need token0 even though user permitted it
        toAmountPairs[0].requestedAmount = 0;

        uint256 startBalanceFrom0 = token0.balanceOf(from);
        uint256 startBalanceFrom1 = token1.balanceOf(from);
        uint256 startBalanceTo0 = token0.balanceOf(escrowAddress);
        uint256 startBalanceTo1 = token1.balanceOf(escrowAddress);

        uint256 escrowBalanceToken0Before = escrow.getBalance(from, token0Address);
        uint256 escrowBalanceToken1Before = escrow.getBalance(from, token1Address);
        assertEq(escrowBalanceToken0Before, 0);
        assertEq(escrowBalanceToken1Before, 0);

        verifier.deposit(permit, toAmountPairs, from, sig);

        assertEq(token0.balanceOf(from), startBalanceFrom0);
        assertEq(token1.balanceOf(from), startBalanceFrom1 - defaultAmount);
        assertEq(token0.balanceOf(escrowAddress), startBalanceTo0);
        assertEq(token1.balanceOf(escrowAddress), startBalanceTo1 + defaultAmount);

        uint256 escrowBalanceToken0After = escrow.getBalance(from, token0Address);
        uint256 escrowBalanceToken1After = escrow.getBalance(from, token1Address);
        assertEq(escrowBalanceToken0After, escrowBalanceToken0Before);
        assertEq(escrowBalanceToken1After, escrowBalanceToken1Before + defaultAmount);
    }

    function testPermitBatchTransferFromSingleRecipient() public {
        uint256 nonce = 0;
        address escrowAddress = address(escrow);
        address token0Address = address(token0);
        address token1Address = address(token1);

        address[] memory tokens = AddressBuilder.fill(1, token0Address).push(token1Address);
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(2, defaultAmount, address(escrow));

        uint256 startBalanceFrom0 = token0.balanceOf(from);
        uint256 startBalanceFrom1 = token1.balanceOf(from);
        uint256 startBalanceTo0 = token0.balanceOf(escrowAddress);
        uint256 startBalanceTo1 = token1.balanceOf(escrowAddress);

        uint256 escrowBalanceToken0Before = escrow.getBalance(from, token0Address);
        uint256 escrowBalanceToken1Before = escrow.getBalance(from, token1Address);
        assertEq(escrowBalanceToken0Before, 0);
        assertEq(escrowBalanceToken1Before, 0);

        snapStart("single recipient 2 tokens");
        verifier.deposit(permit, toAmountPairs, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
        assertEq(token1.balanceOf(from), startBalanceFrom1 - defaultAmount);
        assertEq(token0.balanceOf(escrowAddress), startBalanceTo0 + defaultAmount);
        assertEq(token1.balanceOf(escrowAddress), startBalanceTo1 + defaultAmount);

        uint256 escrowBalanceToken0After = escrow.getBalance(from, token0Address);
        uint256 escrowBalanceToken1After = escrow.getBalance(from, token1Address);
        assertEq(escrowBalanceToken0After, escrowBalanceToken0Before + defaultAmount);
        assertEq(escrowBalanceToken1After, escrowBalanceToken1Before + defaultAmount);
    }

    // function testPermitBatchTransferMultiAddr() public {
    //     uint256 nonce = 0;
    //     // signed spender is address(this)
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
    //     bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

    //     uint256 startBalanceFrom0 = token0.balanceOf(from);
    //     uint256 startBalanceFrom1 = token1.balanceOf(from);
    //     uint256 startBalanceTo0 = token0.balanceOf(address(this));
    //     uint256 startBalanceTo1 = token1.balanceOf(address2);

    //     address[] memory to = AddressBuilder.fill(1, address(this)).push(address2);
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);
    //     permit2.permitTransferFrom(permit, toAmountPairs, from, sig);

    //     assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
    //     assertEq(token0.balanceOf(address(this)), startBalanceTo0 + defaultAmount);

    //     assertEq(token1.balanceOf(from), startBalanceFrom1 - defaultAmount);
    //     assertEq(token1.balanceOf(address2), startBalanceTo1 + defaultAmount);
    // }

    function testPermitBatchTransferSingleRecipientManyTokens() public {
        uint256 nonce = 0;

        address[] memory tokens = AddressBuilder.fill(10, address(token0));
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        uint256 startBalanceFrom0 = token0.balanceOf(from);
        uint256 startBalanceTo0 = token0.balanceOf(address(escrow));

        uint256 escrowBalanceBefore = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceBefore, 0);

        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(10, defaultAmount, address(escrow));

        snapStart("single recipient many tokens");
        verifier.deposit(permit, toAmountPairs, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom0 - 10 * defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo0 + 10 * defaultAmount);

        uint256 escrowBalanceAfter = escrow.getBalance(from, address(token0));
        assertEq(escrowBalanceAfter, escrowBalanceBefore + 10 * defaultAmount);
    }

    function testPermitBatchTransferInvalidAmountsLengthMismatch() public {
        uint256 nonce = 0;

        address[] memory tokens = AddressBuilder.fill(2, address(token0));
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(1, defaultAmount, address(escrow));

        vm.expectRevert(IPermit2.LengthMismatch.selector);
        verifier.deposit(permit, toAmountPairs, from, sig);
    }

    function testGasSinglePermitTransferFrom() public {
        uint256 nonce = 0;
        IPermit2.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), nonce);
        bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address(escrow));

        IPermit2.SignatureTransferDetails memory transferDetails =
            getTransferDetails(address(escrow), defaultAmount);

        snapStart("permitTransferFromSingleToken");
        verifier.deposit(permit, transferDetails, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom - defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo + defaultAmount);
    }

    function testGasSinglePermitBatchTransferFrom() public {
        uint256 nonce = 0;
        address[] memory tokens = AddressBuilder.fill(1, address(token0));
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(1, defaultAmount, address(escrow));

        uint256 startBalanceFrom0 = token0.balanceOf(from);
        uint256 startBalanceTo0 = token0.balanceOf(address(escrow));

        snapStart("permitBatchTransferFromSingleToken");
        verifier.deposit(permit, toAmountPairs, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo0 + defaultAmount);
    }

    function testGasMultiplePermitBatchTransferFrom() public {
        uint256 nonce = 0;
        address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1)).push(address(token1));
        IPermit2.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
        bytes memory sig = getPermitBatchTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR, address(verifier));

        address[] memory to = AddressBuilder.fill(2, address(escrow)).push(address(escrow));
        IPermit2.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(defaultAmount, to);

        uint256 startBalanceFrom0 = token0.balanceOf(from);
        uint256 startBalanceFrom1 = token1.balanceOf(from);
        uint256 startBalanceTo0 = token0.balanceOf(address(escrow));
        uint256 startBalanceTo1 = token1.balanceOf(address(escrow));

        snapStart("permitBatchTransferFromMultipleTokens");
        verifier.deposit(permit, toAmountPairs, from, sig);
        snapEnd();

        assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
        assertEq(token0.balanceOf(address(escrow)), startBalanceTo0 + defaultAmount);
        assertEq(token1.balanceOf(from), startBalanceFrom1 - 2 * defaultAmount);
        assertEq(token1.balanceOf(address(escrow)), startBalanceTo1 + 2 * defaultAmount);
    }

    // function testPermitBatchTransferFromTypedWitness() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);

    //     bytes memory sig = getPermitBatchWitnessSignature(
    //         permit, fromPrivateKey, FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR
    //     );

    //     address[] memory to = AddressBuilder.fill(1, address(address2)).push(address(address0));
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);

    //     uint256 startBalanceFrom0 = token0.balanceOf(from);
    //     uint256 startBalanceFrom1 = token1.balanceOf(from);
    //     uint256 startBalanceTo0 = token0.balanceOf(address2);
    //     uint256 startBalanceTo1 = token1.balanceOf(address0);

    //     snapStart("permitTransferFromBatchTypedWitness");
    //     permit2.permitWitnessTransferFrom(permit, toAmountPairs, from, witness, WITNESS_TYPE_STRING, sig);
    //     snapEnd();

    //     assertEq(token0.balanceOf(from), startBalanceFrom0 - defaultAmount);
    //     assertEq(token1.balanceOf(from), startBalanceFrom1 - defaultAmount);
    //     assertEq(token0.balanceOf(address2), startBalanceTo0 + defaultAmount);
    //     assertEq(token1.balanceOf(address0), startBalanceTo1 + defaultAmount);
    // }

    // function testPermitBatchTransferFromTypedWitnessInvalidType() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
    //     bytes memory sig = getPermitBatchWitnessSignature(
    //         permit, fromPrivateKey, FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR
    //     );

    //     address[] memory to = AddressBuilder.fill(1, address(address2)).push(address(address0));
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);

    //     vm.expectRevert(SignatureVerification.InvalidSigner.selector);
    //     permit2.permitWitnessTransferFrom(permit, toAmountPairs, from, witness, "fake type", sig);
    // }

    // function testPermitBatchTransferFromTypedWitnessInvalidTypeHash() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
    //     bytes memory sig =
    //         getPermitBatchWitnessSignature(permit, fromPrivateKey, "fake typehash", witness, DOMAIN_SEPARATOR);

    //     address[] memory to = AddressBuilder.fill(1, address(address2)).push(address(address0));
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);

    //     vm.expectRevert(SignatureVerification.InvalidSigner.selector);
    //     permit2.permitWitnessTransferFrom(permit, toAmountPairs, from, witness, WITNESS_TYPE_STRING, sig);
    // }

    // function testPermitBatchTransferFromTypedWitnessInvalidWitness() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     address[] memory tokens = AddressBuilder.fill(1, address(token0)).push(address(token1));
    //     ISignatureTransfer.PermitBatchTransferFrom memory permit = defaultERC20PermitMultiple(tokens, nonce);
    //     bytes memory sig = getPermitBatchWitnessSignature(
    //         permit, fromPrivateKey, FULL_EXAMPLE_WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR
    //     );

    //     address[] memory to = AddressBuilder.fill(1, address(address2)).push(address(address0));
    //     ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
    //         StructBuilder.fillSigTransferDetails(defaultAmount, to);

    //     vm.expectRevert(SignatureVerification.InvalidSigner.selector);
    //     permit2.permitWitnessTransferFrom(
    //         permit, toAmountPairs, from, keccak256(abi.encodePacked("bad witness")), WITNESS_TYPE_STRING, sig
    //     );
    // }

    // function testInvalidateUnorderedNonces() public {
    //     ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitTransfer(address(token0), 0);
    //     bytes memory sig = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

    //     uint256 bitmap = permit2.nonceBitmap(from, 0);
    //     assertEq(bitmap, 0);

    //     vm.prank(from);
    //     vm.expectEmit(true, false, false, true);
    //     emit UnorderedNonceInvalidation(from, 0, 1);
    //     permit2.invalidateUnorderedNonces(0, 1);
    //     bitmap = permit2.nonceBitmap(from, 0);
    //     assertEq(bitmap, 1);

    //     ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address2, defaultAmount);

    //     vm.expectRevert(InvalidNonce.selector);
    //     permit2.permitTransferFrom(permit, transferDetails, from, sig);
    // }

    // function testPermitTransferFromTypedWitness() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitWitnessTransfer(address(token0), nonce);
    //     bytes memory sig = getPermitWitnessTransferSignature(
    //         permit, fromPrivateKey, FULL_EXAMPLE_WITNESS_TYPEHASH, witness, DOMAIN_SEPARATOR
    //     );

    //     uint256 startBalanceFrom = token0.balanceOf(from);
    //     uint256 startBalanceTo = token0.balanceOf(address2);

    //     ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address2, defaultAmount);

    //     snapStart("permitTransferFromTypedWitness");
    //     permit2.permitWitnessTransferFrom(permit, transferDetails, from, witness, WITNESS_TYPE_STRING, sig);
    //     snapEnd();

    //     assertEq(token0.balanceOf(from), startBalanceFrom - defaultAmount);
    //     assertEq(token0.balanceOf(address2), startBalanceTo + defaultAmount);
    // }

    // function testPermitTransferFromTypedWitnessInvalidType() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitWitnessTransfer(address(token0), nonce);
    //     bytes memory sig = getPermitWitnessTransferSignature(
    //         permit, fromPrivateKey, FULL_EXAMPLE_WITNESS_TYPEHASH, witness, DOMAIN_SEPARATOR
    //     );

    //     ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address2, defaultAmount);

    //     vm.expectRevert(SignatureVerification.InvalidSigner.selector);
    //     permit2.permitWitnessTransferFrom(permit, transferDetails, from, witness, "fake typedef", sig);
    // }

    // function testPermitTransferFromTypedWitnessInvalidTypehash() public {
    //     uint256 nonce = 0;
    //     MockWitness memory witnessData = MockWitness(10000000, address(5), true);
    //     bytes32 witness = keccak256(abi.encode(witnessData));
    //     ISignatureTransfer.PermitTransferFrom memory permit = defaultERC20PermitWitnessTransfer(address(token0), nonce);
    //     bytes memory sig =
    //         getPermitWitnessTransferSignature(permit, fromPrivateKey, "fake typehash", witness, DOMAIN_SEPARATOR);

    //     ISignatureTransfer.SignatureTransferDetails memory transferDetails = getTransferDetails(address2, defaultAmount);

    //     vm.expectRevert(SignatureVerification.InvalidSigner.selector);
    //     permit2.permitWitnessTransferFrom(permit, transferDetails, from, witness, WITNESS_TYPE_STRING, sig);
    // }
}

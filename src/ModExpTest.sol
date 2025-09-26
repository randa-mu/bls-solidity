pragma solidity ^0.8;

import {Test} from "forge-std-1.10.0/src/Test.sol";

import {ModexpInverse} from "src/libraries/ModExp.sol";

contract ModexpTest is Test {
    // per https://www.rfc-editor.org/rfc/rfc9380.html#section-4-4.6.1, if the input is 0 the correct output is 0.
    function test_inv_zero() public pure {
        uint256 r = ModexpInverse.run(0);
        assertEq(r, 0);
    }
}

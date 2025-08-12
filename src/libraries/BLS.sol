// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import {ModexpInverse, ModexpSqrt, ModUtils} from "./ModExp.sol";

/// @title  Boneh–Lynn–Shacham (BLS) signature scheme on Barreto-Naehrig 254 bit curve (BN-254) used to verify BLS signaturess on the BN254 curve in Solidity
/// @notice We use BLS signature aggregation to reduce the size of signature data to store on chain.
/// @dev We can use G1 points for signatures and messages, and G2 points for public keys or vice versa
/// @dev G1 is 64 bytes (uint256[2] in Solidity) and G2 is 128 bytes (uint256[4] in Solidity)
/// @dev Adapted from https://github.com/kevincharm/bls-bn254.git
library BLS {
    struct PointG1 {
        uint256 x;
        uint256 y;
    }

    struct PointG2 {
        uint256[2] x; // x coordinate (represented as 2 uint256 values) / Fp2 coordinates
        uint256[2] y; // y coordinate (represented as 2 uint256 values) / Fp2 coordinates
    }

    // GfP2 implements a field of size p² as a quadratic extension of the base field.
    struct GfP2 {
        uint256 x;
        uint256 y;
    }

    // Field order
    // p is a prime over which we form a basic field
    // go-ethereum/crypto/bn256/cloudflare/constants.go
    uint256 private constant N = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Generator of G1
    uint256 private constant G1_X = 1;
    uint256 private constant G1_Y = 2;

    // Negated generator of G1
    uint256 private constant N_G1_X = 1;
    uint256 private constant N_G1_Y = 21888242871839275222246405745257275088696311157297823662689037894645226208581;

    // Negated generator of G2
    uint256 private constant N_G2_X1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 private constant N_G2_X0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 private constant N_G2_Y1 = 17805874995975841540914202342111839520379459829704422454583296818431106115052;
    uint256 private constant N_G2_Y0 = 13392588948715843804641432497768002650278120570034223513918757245338268106653;

    uint256 private constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 private constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

    /// @notice Param A of BN254
    uint256 private constant A = 0;
    /// @notice Param B of BN254
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 = 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 = 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    error BNAddFailed(uint256[4] input);
    error InvalidFieldElement(uint256 x);
    error MapToPointFailed(uint256 noSqrt);
    error InvalidDSTLength(bytes dst);
    error ModExpFailed(uint256 base, uint256 exponent, uint256 modulus);

    /// @notice Computes the negation of a point on the G1 curve.
    /// @dev Returns the negation of the input point p on the elliptic curve.
    ///      If the point is at infinity (x = 0, y = 0), it returns the point
    ///      itself. Otherwise, it returns a new point with the same x-coordinate
    ///      and the negated y-coordinate modulo the curve's prime N.
    /// @param p The point on the G1 curve to negate.
    /// @return The negated point on the G1 curve, such that p + negate(p) = 0.
    function negate(PointG1 memory p) internal pure returns (PointG1 memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) {
            return PointG1(0, 0);
        } else {
            return PointG1(p.x, N - (p.y % N));
        }
    }

    /// @notice Adds two points on the G1 curve.
    /// @dev Uses the precompiled contract at address 0x06 to perform
    ///      elliptic curve point addition in the G1 group. This function
    ///      returns the resulting point r = p1 + p2.
    /// @dev Reverts if the point addition operation fails.
    /// @param p1 The first point on the G1 curve.
    /// @param p2 The second point on the G1 curve.
    /// @return r The resulting point from adding p1 and p2 on the G1 curve.
    function addG1Points(PointG1 memory p1, PointG1 memory p2) internal view returns (PointG1 memory r) {
        uint256[4] memory input;
        input[0] = p1.x;
        input[1] = p1.y;
        input[2] = p2.x;
        input[3] = p2.y;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }

        require(success, "G1 addition failed");
    }

    /// @notice Performs scalar multiplication of a point on the G1 curve.
    /// @dev Uses the precompiled contract at address 0x07 to perform
    ///      scalar multiplication of a point on the G1 curve, i.e.,
    ///      computes r = s * p, where s is the scalar and p is the point.
    /// @dev Reverts if the scalar multiplication operation fails.
    /// @param p The point on the G1 curve to be multiplied.
    /// @param s The scalar value to multiply the point by.
    /// @return r The resulting point from scalar multiplication, r = s * p.
    function scalarMulG1Point(PointG1 memory p, uint256 s) internal view returns (PointG1 memory r) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "G1 scalar multiplication failed");
    }

    /// @notice Compute a scalar multiplication with a scalar and the base point.
    function scalarMulG1Base(uint256 s) internal view returns (PointG1 memory r) {
        uint256[3] memory input;
        input[0] = G1_X;
        input[1] = G1_Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "G1 scalar multiplication failed");
    }

    /// @notice Verify signed message on g1 against signature on g1 and public key on g2
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingle(PointG1 memory signature, PointG2 memory pubkey, PointG1 memory message)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input = [
            signature.x,
            signature.y,
            N_G2_X1,
            N_G2_X0,
            N_G2_Y1,
            N_G2_Y0,
            message.x,
            message.y,
            pubkey.x[1],
            pubkey.x[0],
            pubkey.y[1],
            pubkey.y[0]
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Verifies that the same scalar is used in both rG1 and rG2.
    function verifyEqualityG1G2(PointG1 memory rG1, PointG2 memory rG2)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input =
            [rG1.x, rG1.y, N_G2_X1, N_G2_X0, N_G2_Y1, N_G2_Y0, G1_X, G1_Y, rG2.x[1], rG2.x[0], rG2.y[1], rG2.y[0]];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Verify signed message on g2 against signature on g2 and public key on g1
    /// @param signature Signature to check
    /// @param pubkey Public key of signer
    /// @param message Message to check
    /// @return pairingSuccess bool indicating if the pairing check was successful
    /// @return callSuccess bool indicating if the static call to the evm precompile was successful
    function verifySingleG2(PointG2 memory signature, PointG1 memory pubkey, PointG2 memory message)
        internal
        view
        returns (bool pairingSuccess, bool callSuccess)
    {
        uint256[12] memory input = [
            N_G1_X,
            N_G1_Y,
            signature.x[1],
            signature.x[0],
            signature.y[1],
            signature.y[0],
            pubkey.x,
            pubkey.y,
            message.x[1],
            message.x[0],
            message.y[1],
            message.y[0]
        ];
        uint256[1] memory out;
        assembly {
            callSuccess := staticcall(sub(gas(), 2000), 8, input, 384, out, 0x20)
        }
        return (out[0] != 0, callSuccess);
    }

    /// @notice Hash to BN254 G1
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return point in G1
    function hashToPoint(bytes memory domain, bytes memory message) internal view returns (PointG1 memory point) {
        uint256[2] memory u = hashToField(domain, message);
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        if (!success) revert BNAddFailed(bnAddInput);
        point = PointG1({x: p0[0], y: p0[1]});
        return point;
    }

    /// @notice Check if point in g1 is a valid
    /// @param point The point on g1 to check
    function isValidPointG1(PointG1 memory point) internal pure returns (bool) {
        if ((point.x >= N) || (point.y >= N)) {
            return false;
        } else {
            return isOnCurveG1(point);
        }
    }

    /// @notice Check if point is a valid g2 point
    /// @param point the point to check
    function isValidPointG2(PointG2 memory point) internal pure returns (bool) {
        if ((point.x[0] >= N) || (point.x[1] >= N) || (point.y[0] >= N || (point.y[1] >= N))) {
            return false;
        } else {
            return isOnCurveG2(point);
        }
    }

    /// @notice Check if `point` is in G1
    /// @param p Point to check
    function isOnCurveG1(PointG1 memory p) internal pure returns (bool _isOnCurve) {
        uint256[2] memory point = [p.x, p.y];
        assembly {
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            let t2 := mulmod(t0, t0, N)
            t2 := mulmod(t2, t0, N)
            t2 := addmod(t2, 3, N)
            t1 := mulmod(t1, t1, N)
            _isOnCurve := eq(t1, t2)
        }
    }

    /// @notice Check if `point` is in G2
    /// @param p Point to check
    function isOnCurveG2(PointG2 memory p) internal pure returns (bool _isOnCurve) {
        uint256[4] memory point = [p.x[0], p.x[1], p.y[0], p.y[1]];
        assembly {
            // x0, x1
            let t0 := mload(point)
            let t1 := mload(add(point, 32))
            // x0 ^ 2
            let t2 := mulmod(t0, t0, N)
            // x1 ^ 2
            let t3 := mulmod(t1, t1, N)
            // 3 * x0 ^ 2
            let t4 := add(add(t2, t2), t2)
            // 3 * x1 ^ 2
            let t5 := addmod(add(t3, t3), t3, N)
            // x0 * (x0 ^ 2 - 3 * x1 ^ 2)
            t2 := mulmod(add(t2, sub(N, t5)), t0, N)
            // x1 * (3 * x0 ^ 2 - x1 ^ 2)
            t3 := mulmod(add(t4, sub(N, t3)), t1, N)

            // x ^ 3 + b
            t0 := addmod(t2, 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5, N)
            t1 := addmod(t3, 0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2, N)

            // y0, y1
            t2 := mload(add(point, 64))
            t3 := mload(add(point, 96))
            // y ^ 2
            t4 := mulmod(addmod(t2, t3, N), addmod(t2, sub(N, t3), N), N)
            t3 := mulmod(shl(1, t2), t3, N)

            // y ^ 2 == x ^ 3 + b
            _isOnCurve := and(eq(t0, t4), eq(t1, t3))
        }
    }

    /// @notice Check if `signature` is a valid signature
    /// @param signature Signature to check
    function isValidSignature(uint256[2] memory signature) internal pure returns (bool) {
        if ((signature[0] >= N) || (signature[1] >= N)) {
            return false;
        }
        return isOnCurveG1(PointG1({x: signature[0], y: signature[1]}));
    }

    /// @notice Check if `publicKey` is a valid public key
    /// @param publicKey PK to check
    function isValidPublicKey(uint256[4] memory publicKey) internal pure returns (bool) {
        if ((publicKey[0] >= N) || (publicKey[1] >= N) || (publicKey[2] >= N || (publicKey[3] >= N))) {
            return false;
        }
        return isOnCurveG2(PointG2({x: [publicKey[0], publicKey[1]], y: [publicKey[2], publicKey[3]]}));
    }

    /// @notice Unmarshals a point on G1 from bytes in an uncompressed form.
    function g1Unmarshal(bytes memory m) internal pure returns (PointG1 memory) {
        require(m.length == 64, "Invalid G1 bytes length");

        bytes32 x;
        bytes32 y;

        assembly {
            x := mload(add(m, 0x20))
            y := mload(add(m, 0x40))
        }

        return PointG1(uint256(x), uint256(y));
    }

    /// @notice Marshals a point on G1 to bytes form.
    function g1Marshal(PointG1 memory point) internal pure returns (bytes memory) {
        bytes memory m = new bytes(64);
        bytes32 x = bytes32(point.x);
        bytes32 y = bytes32(point.y);

        assembly {
            mstore(add(m, 32), x)
            mstore(add(m, 64), y)
        }

        return m;
    }

    /// @dev Unmarshals a point on G2 from bytes in an uncompressed form.
    function g2Unmarshal(bytes memory m) internal pure returns (PointG2 memory) {
        require(m.length == 128, "Invalid G2 bytes length");

        uint256 xx;
        uint256 xy;
        uint256 yx;
        uint256 yy;

        assembly {
            xx := mload(add(m, 0x20))
            xy := mload(add(m, 0x40))
            yx := mload(add(m, 0x60))
            yy := mload(add(m, 0x80))
        }

        return PointG2([xx, xy], [yx, yy]);
    }

    function g2Marshal(PointG2 memory point) internal pure returns (bytes memory) {
        bytes memory m = new bytes(128);
        bytes32 xx = bytes32(point.x[0]);
        bytes32 xy = bytes32(point.x[1]);
        bytes32 yx = bytes32(point.y[0]);
        bytes32 yy = bytes32(point.y[1]);

        assembly {
            mstore(add(m, 0x20), xx)
            mstore(add(m, 0x40), xy)
            mstore(add(m, 0x60), yx)
            mstore(add(m, 0x80), yy)
        }

        return m;
    }

    /// @notice sqrt(xx) mod N
    /// @param xx Input
    function sqrt(uint256 xx) internal pure returns (uint256 x, bool hasRoot) {
        x = ModexpSqrt.run(xx);
        hasRoot = mulmod(x, x, N) == xx;
    }

    /// @notice a^{-1} mod N
    /// @param a Input
    function inverse(uint256 a) internal pure returns (uint256) {
        return ModexpInverse.run(a);
    }

    /// @notice Hash a message to the field
    /// @param domain Domain separation tag
    /// @param message Message to hash
    function hashToField(bytes memory domain, bytes memory message) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsgTo96(domain, message);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return [a0, a1];
    }

    function hashToFieldSingle(bytes memory domain, bytes memory message) internal pure returns (uint256) {
        bytes memory _msg = expandMsg(domain, message, 48);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, N), u0, N)
        }
        return a0;
    }

    /// @notice Expand arbitrary message to n bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param DST Domain separation tag
    /// @param message The message to expand
    /// @param n_bytes The number of bytes to extend to
    function expandMsg(bytes memory DST, bytes memory message, uint8 n_bytes) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(zpad, message, uint8(0), n_bytes, uint8(0), DST, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), DST, uint8(domainLen));
        bytes32 bi = keccak256(b_i);
        bytes memory out = new bytes(n_bytes);
        uint256 ell = (n_bytes + uint256(31)) >> 5;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), DST, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Expand arbitrary message to 96 pseudorandom bytes, as described
    ///     in rfc9380 section 5.3.1, using H = keccak256.
    /// @param DST Domain separation tag
    /// @param message Message to expand
    function expandMsgTo96(bytes memory DST, bytes memory message) internal pure returns (bytes memory) {
        uint256 domainLen = DST.length;
        if (domainLen > 255) {
            revert InvalidDSTLength(DST);
        }
        bytes memory zpad = new bytes(136);
        bytes memory b_0 = abi.encodePacked(zpad, message, uint8(0), uint8(96), uint8(0), DST, uint8(domainLen));
        bytes32 b0 = keccak256(b_0);

        bytes memory b_i = abi.encodePacked(b0, uint8(1), DST, uint8(domainLen));
        bytes32 bi = keccak256(b_i);

        bytes memory out = new bytes(96);
        uint256 ell = 3;
        for (uint256 i = 1; i < ell; i++) {
            b_i = abi.encodePacked(b0 ^ bi, uint8(1 + i), DST, uint8(domainLen));
            assembly {
                let p := add(32, out)
                p := add(p, mul(32, sub(i, 1)))
                mstore(p, bi)
            }
            bi = keccak256(b_i);
        }
        assembly {
            let p := add(32, out)
            p := add(p, mul(32, sub(ell, 1)))
            mstore(p, bi)
        }
        return out;
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(uint256 u) internal view returns (uint256[2] memory p) {
        if (u >= N) revert InvalidFieldElement(u);

        uint256 tv1 = mulmod(mulmod(u, u, N), C1, N);
        uint256 tv2 = addmod(1, tv1, N);
        tv1 = addmod(1, N - tv1, N);
        uint256 tv3 = inverse(mulmod(tv1, tv2, N));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, N), tv3, N), C3, N);
        uint256 x1 = addmod(C2, N - tv5, N);
        uint256 x2 = addmod(C2, tv5, N);
        uint256 tv7 = mulmod(tv2, tv2, N);
        uint256 tv8 = mulmod(tv7, tv3, N);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, N), N), N);

        bool hasRoot;
        uint256 gx;
        if (legendre(g(x1)) == 1) {
            p[0] = x1;
            gx = g(x1);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else if (legendre(g(x2)) == 1) {
            p[0] = x2;
            gx = g(x2);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        } else {
            p[0] = x3;
            gx = g(x3);
            (p[1], hasRoot) = sqrt(gx);
            if (!hasRoot) revert MapToPointFailed(gx);
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = N - p[1];
        }
    }

    /// @notice g(x) = y^2 = x^3 + 3
    function g(uint256 x) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, N), x, N), B, N);
    }

    /// @notice https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    function sgn0(uint256 x) private pure returns (uint256) {
        return x % 2;
    }

    /// @notice Compute Legendre symbol of u
    /// @param u Field element
    /// @return 1 if u is a quadratic residue, -1 if not, or 0 if u = 0 (mod p)
    function legendre(uint256 u) private view returns (int8) {
        uint256 x = modexpLegendre(u);
        if (x == N - 1) {
            return -1;
        }
        if (x != 0 && x != 1) {
            revert MapToPointFailed(u);
        }
        return int8(int256(x));
    }

    /// @notice This is cheaper than an addchain for exponent (N-1)/2
    function modexpLegendre(uint256 u) private view returns (uint256 output) {
        bytes memory input = new bytes(192);
        bool success;
        assembly {
            let p := add(input, 32)
            mstore(p, 32) // len(u)
            p := add(p, 32)
            mstore(p, 32) // len(exp)
            p := add(p, 32)
            mstore(p, 32) // len(mod)
            p := add(p, 32)
            mstore(p, u) // u
            p := add(p, 32)
            mstore(p, C5) // (N-1)/2
            p := add(p, 32)
            mstore(p, N) // N

            success :=
                staticcall(
                    gas(),
                    5,
                    add(input, 32),
                    192,
                    0x00, // scratch space <- result
                    32
                )
            output := mload(0x00) // output <- result
        }
        if (!success) {
            revert ModExpFailed(u, C5, N);
        }
    }
}

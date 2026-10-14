// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AttestedKeyVault} from "../src/AttestedKeyVault.sol";

/// Minimal Hevm cheatcode interface (forge-std deliberately not vendored).
interface Vm {
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external pure returns (address);
    function chainId(uint256 newChainId) external;
    function warp(uint256 newTimestamp) external;
    function prank(address sender) external;
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function readFile(string calldata path) external view returns (string memory);
    function projectRoot() external view returns (string memory);
}

/// @dev Test harness: overrides the Sapphire ECIES sealing with a mock seal
/// whose "enclave-side" unseal is also provided here. The security-critical
/// logic under test is the attestation authorization gate, not Sapphire's
/// precompiles (platform TCB on a real deployment).
contract TestableVault is AttestedKeyVault {
    constructor(address owner_, address verifier_, bool enforceSapphireChainId_, bool burnOnRelease_)
        AttestedKeyVault(owner_, verifier_, enforceSapphireChainId_, burnOnRelease_)
    {}

    function _sealTo(bytes32 channelKey, bytes32 challenge, bytes memory plaintext)
        internal
        pure
        override
        returns (bytes32 ephPubKey, Seal memory sealOut)
    {
        ephPubKey = keccak256(abi.encodePacked("mock-eph", challenge));
        bytes32 k = keccak256(abi.encodePacked("mock-seal", channelKey, challenge));
        bytes memory ct = new bytes(plaintext.length);
        for (uint256 i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ k[i % 32];
        }
        sealOut = Seal({ephKey: ephPubKey, nonce: keccak256(abi.encodePacked("nonce", challenge)), ciphertext: ct});
    }

    /// @dev The enclave side of the mock seal (mirrors X25519 shared-secret
    /// agreement + authenticated decryption in the real path).
    function mockUnseal(bytes32 channelKey, bytes32 challenge, bytes memory ct)
        external
        pure
        returns (bytes memory)
    {
        bytes32 k = keccak256(abi.encodePacked("mock-seal", channelKey, challenge));
        bytes memory pt = new bytes(ct.length);
        for (uint256 i = 0; i < ct.length; i++) {
            pt[i] = ct[i] ^ k[i % 32];
        }
        return pt;
    }
}

contract AttestedKeyVaultTest {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // The test contract is the vault owner/admin everywhere; the verifier
    // address is derived from VERIFIER_PK via vm.addr (== ecrecover's answer).
    address internal constant STRANGER = address(0xBAD);

    // Enclave identity pins (on-chain they are keccak256 of the 48-byte SNP
    // LAUNCH_DIGEST and of the software binding — see verifier crate).
    bytes32 internal constant MEASUREMENT = keccak256("OCI-E5-SEV-SNP-MEASUREMENT");
    bytes32 internal constant SOFTWARE = keccak256("binary+manifest");
    bytes32 internal constant CHANNEL = keccak256("enclave-x25519-pub");

    uint256 internal constant VERIFIER_PK = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF;

    TestableVault internal vault;
    bytes internal constant SECRET = hex"52697665722073747978206f66204d616420536369656e6365"; // "River styx of Mad Science"

    function setUp() public {
        // The vault must trust the address that corresponds to VERIFIER_PK —
        // vm.addr derives it exactly as the contract's ecrecover will.
        vault = new TestableVault(address(this), vm.addr(VERIFIER_PK), false, true);
        vm.chainId(23293); // Sapphire mainnet chain id
    }

    // -------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Full happy path prelude: challenge -> digest -> verifier signature.
    function _honestAuth()
        internal
        returns (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig)
    {
        bytes32 challenge = vault.issueChallenge();
        a = AttestedKeyVault.ReleaseAuth({
            requester: address(this),
            measurementId: MEASUREMENT,
            softwareId: SOFTWARE,
            challenge: challenge,
            channelKey: CHANNEL,
            expiry: uint64(block.timestamp + 1 hours)
        });
        sig = _sign(VERIFIER_PK, vault.releaseDigest(a));
    }

    // -------------------------------------------------------------------
    // administration
    // -------------------------------------------------------------------

    function test_OwnerSetsSecretAndApprovals() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        assertTrue(vault.secretSet(), "secretSet");
        assertTrue(vault.approvedMeasurement(MEASUREMENT), "measurement approved");
    }

    function test_NonOwnerCannotAdmin() public {
        TestableVault v = new TestableVault(STRANGER, vm.addr(VERIFIER_PK), false, true);
        vm.expectRevert(AttestedKeyVault.NotOwner.selector);
        v.setSecret(SECRET);
    }

    // -------------------------------------------------------------------
    // release protocol: happy path
    // -------------------------------------------------------------------

    function test_HappyPathReleasesSealedSecret() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);

        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        bytes memory ct = vault.release(a, sig);

        // The enclave (channel-key holder) can open the seal; nobody else can.
        assertEqBytes(vault.mockUnseal(CHANNEL, a.challenge, ct), SECRET, "opened == secret");
        assertTrue(
            keccak256(vault.mockUnseal(keccak256("wrong-channel"), a.challenge, ct))
                != keccak256(SECRET),
            "wrong channel key must not yield the secret"
        );

        // One-shot vault: secret zeroed, challenge dead.
        assertTrue(!vault.secretSet(), "burned");
        assertTrue(vault.challengeUsed(a.challenge), "challenge used");
        (bytes32 ephKey,, bytes memory stored) = _sealTuple(vault.sealedSecret(a.challenge));
        assertEqBytes(stored, ct, "stored ciphertext matches");
        assertTrue(ephKey != bytes32(0), "eph key set");
    }

    function test_ReplayFailsClosed() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vault.release(a, sig);

        // Replay must fail closed (first failing check wins; all are fatal).
        try vault.release(a, sig) {
            revert("replay must revert");
        } catch (bytes memory reason) {
            bytes4 sel = _selector(reason);
            assertTrue(
                sel == AttestedKeyVault.SecretNotSet.selector || sel == AttestedKeyVault.ChallengeNotLive.selector
                    || sel == AttestedKeyVault.ChallengeAlreadyUsed.selector,
                "fail-closed replay"
            );
        }
    }

    function test_ReissueInvalidatesOutstandingChallenge() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        bytes32 c1 = vault.issueChallenge();
        bytes32 c2 = vault.issueChallenge();
        assertTrue(c1 != c2, "distinct challenges");

        AttestedKeyVault.ReleaseAuth memory a = AttestedKeyVault.ReleaseAuth({
            requester: address(this),
            measurementId: MEASUREMENT,
            softwareId: SOFTWARE,
            challenge: c1, // stale: superseded by c2
            channelKey: CHANNEL,
            expiry: uint64(block.timestamp + 1 hours)
        });
        bytes memory sig = _sign(VERIFIER_PK, vault.releaseDigest(a));
        vm.expectRevert(AttestedKeyVault.ChallengeNotLive.selector);
        vault.release(a, sig);
    }

    // -------------------------------------------------------------------
    // release protocol: negatives
    // -------------------------------------------------------------------

    function test_RevertWrongSigner() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a,) = _honestAuth();
        uint256 badPk = uint256(keccak256("not the verifier"));
        bytes memory sig = _sign(badPk, vault.releaseDigest(a));
        vm.expectRevert(AttestedKeyVault.BadAuthorization.selector);
        vault.release(a, sig);
    }

    function test_RevertExpired() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(AttestedKeyVault.AuthorizationExpired.selector);
        vault.release(a, sig);
    }

    function test_RevertUnapprovedMeasurement() public {
        vault.setSecret(SECRET);
        vault.setApprovedSoftware(SOFTWARE, true); // measurement intentionally NOT approved
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vm.expectRevert(AttestedKeyVault.MeasurementNotApproved.selector);
        vault.release(a, sig);
    }

    function test_RevertUnapprovedSoftware() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true); // software intentionally NOT approved
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vm.expectRevert(AttestedKeyVault.SoftwareNotApproved.selector);
        vault.release(a, sig);
    }

    function test_RevertPaused() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vault.setPaused(true);
        vm.expectRevert(AttestedKeyVault.IsPaused.selector);
        vault.release(a, sig);
    }

    function test_RevertStolenAuthByOtherAccount() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        // Enclave A (this contract) builds a valid auth; STRANGER replays it.
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vm.prank(STRANGER);
        vm.expectRevert(AttestedKeyVault.WrongRequester.selector);
        vault.release(a, sig);
    }

    function test_RevertZeroChannelKey() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        bytes32 c = vault.issueChallenge();
        AttestedKeyVault.ReleaseAuth memory a = AttestedKeyVault.ReleaseAuth({
            requester: address(this),
            measurementId: MEASUREMENT,
            softwareId: SOFTWARE,
            challenge: c,
            channelKey: bytes32(0),
            expiry: uint64(block.timestamp + 1 hours)
        });
        bytes memory sig = _sign(VERIFIER_PK, vault.releaseDigest(a));
        vm.expectRevert(AttestedKeyVault.ZeroChannelKey.selector);
        vault.release(a, sig);
    }

    function test_RevertNoSecret() public {
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();
        vm.expectRevert(AttestedKeyVault.SecretNotSet.selector);
        vault.release(a, sig);
    }

    // -------------------------------------------------------------------
    // Sapphire-only guard
    // -------------------------------------------------------------------

    function test_RevertNonSapphireChainWhenEnforced() public {
        vm.chainId(1); // Ethereum mainnet
        TestableVault v = new TestableVault(address(this), vm.addr(VERIFIER_PK), true, true);
        v.setSecret(SECRET);
        v.setApprovedMeasurement(MEASUREMENT, true);
        v.setApprovedSoftware(SOFTWARE, true);
        bytes32 c = v.issueChallenge();
        AttestedKeyVault.ReleaseAuth memory a = AttestedKeyVault.ReleaseAuth({
            requester: address(this),
            measurementId: MEASUREMENT,
            softwareId: SOFTWARE,
            challenge: c,
            channelKey: CHANNEL,
            expiry: uint64(block.timestamp + 1 hours)
        });
        bytes memory sig = _sign(VERIFIER_PK, v.releaseDigest(a));
        vm.expectRevert(AttestedKeyVault.WrongChain.selector);
        v.release(a, sig);
    }

    // -------------------------------------------------------------------
    // governance
    // -------------------------------------------------------------------

    function test_RescindWithdrawsSecret() public {
        vault.setSecret(SECRET);
        vault.rescind();
        assertTrue(!vault.secretSet(), "rescinded");
    }

    function test_SetVerifierRotatesTrust() public {
        vault.setSecret(SECRET);
        vault.setApprovedMeasurement(MEASUREMENT, true);
        vault.setApprovedSoftware(SOFTWARE, true);
        (AttestedKeyVault.ReleaseAuth memory a, bytes memory sig) = _honestAuth();

        // Owner rotates verifier BEFORE release: old sig no longer valid.
        uint256 newPk = 0xC0FFEE;
        vault.setVerifier(vm.addr(newPk));
        bytes memory sigNew = _sign(newPk, vault.releaseDigest(a));
        bytes memory ct = vault.release(a, sigNew);
        assertTrue(ct.length == SECRET.length, "released under new verifier");
        assertTrue(keccak256(sig) != keccak256(sigNew), "different sigs");
    }

    // -------------------------------------------------------------------
    // cross-language digest parity (fixtures/parity.json is produced by the
    // Rust verifier crate; regenerate with `cargo run --bin gen-parity`
    // and update BOTH together — same discipline as verifiedUniqueAliases/
    // verify.html vs src/oci_snp.rs)
    // -------------------------------------------------------------------

    function test_ParityDigestMatchesRustSigner() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/../fixtures/parity.json"));

        bytes memory digest = _jsonBytes(json, "eip191Digest");
        bytes memory sig = _jsonBytes(json, "signature");
        address signer = _jsonAddr(json, "signer");

        bytes32 d;
        assembly {
            d := mload(add(digest, 32))
        }
        (uint8 v, bytes32 r, bytes32 s) = _split(sig);
        require(ecrecover(d, v, r, s) == signer, "parity: signer mismatch");

        // Recompute struct hash + EIP-191 wrap in Solidity from fixture fields.
        bytes32 recomputed = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encode(
                        vault.RELEASE_TYPEHASH(),
                        _jsonAddr(json, "vault"),
                        _jsonUint(json, "chainId"),
                        _jsonAddr(json, "requester"),
                        _jsonBytes32(json, "measurementId"),
                        _jsonBytes32(json, "softwareId"),
                        _jsonBytes32(json, "challenge"),
                        _jsonBytes32(json, "channelKey"),
                        uint64(_jsonUint(json, "expiry"))
                    )
                )
            )
        );
        require(recomputed == d, "parity: digest mismatch");
    }

    // -------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------

    function _selector(bytes memory reason) internal pure returns (bytes4 s) {
        require(reason.length >= 4, "empty revert");
        assembly {
            s := mload(add(reason, 32))
        }
    }

    function assertTrue(bool cond, string memory msg_) internal pure {
        require(cond, msg_);
    }

    function assertEqBytes(bytes memory a, bytes memory b, string memory msg_) internal pure {
        require(keccak256(a) == keccak256(b), msg_);
    }

    function _sealTuple(AttestedKeyVault.Seal memory s)
        internal
        pure
        returns (bytes32 ephKey, bytes32 nonce, bytes memory ciphertext)
    {
        return (s.ephKey, s.nonce, s.ciphertext);
    }

    function _split(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "sig len");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    // ---- minimal flat-JSON extractors for the parity fixture -------------
    // Fixture schema: every value is a quoted "0x..." hex string, formatted
    // as `"key": "0x..."` exactly (see gen-parity in the Rust crate).

    function _jsonBytes(string memory json, string memory key) internal pure returns (bytes memory) {
        return _hexToBytes(_jsonHex(json, key));
    }

    function _jsonBytes32(string memory json, string memory key) internal pure returns (bytes32) {
        bytes memory b = _hexToBytes(_jsonHex(json, key));
        require(b.length == 32, "bytes32 len");
        bytes32 out;
        for (uint256 i = 0; i < 32; i++) {
            out |= bytes32(b[i]) >> (8 * i);
        }
        return out;
    }

    function _jsonAddr(string memory json, string memory key) internal pure returns (address) {
        return address(uint160(_jsonUint(json, key)));
    }

    function _jsonUint(string memory json, string memory key) internal pure returns (uint256 n) {
        bytes memory h = bytes(_jsonHex(json, key));
        uint256 start = 0;
        if (h.length >= 2 && h[0] == "0" && (h[1] == "x" || h[1] == "X")) {
            start = 2; // skip the 0x prefix
        }
        for (uint256 i = start; i < h.length; i++) {
            n = n * 16 + _nibble(h[i]);
        }
    }

    function _jsonHex(string memory json, string memory key) internal pure returns (string memory) {
        bytes memory j = bytes(json);
        bytes memory k = bytes(string.concat("\"", key, "\": \""));
        uint256 i = 0;
        while (i + k.length <= j.length) {
            bool match_ = true;
            for (uint256 x = 0; x < k.length; x++) {
                if (j[i + x] != k[x]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) {
                uint256 start = i + k.length;
                uint256 end = start;
                while (end < j.length && j[end] != "\"") {
                    end++;
                }
                bytes memory out = new bytes(end - start);
                for (uint256 x = 0; x < out.length; x++) {
                    out[x] = j[start + x];
                }
                return string(out);
            }
            i++;
        }
        revert("key not found");
    }

    function _hexToBytes(string memory hexStr) internal pure returns (bytes memory out) {
        bytes memory h = bytes(hexStr);
        require(h.length >= 2 && h[0] == "0" && (h[1] == "x" || h[1] == "X"), "0x prefix");
        uint256 n = (h.length - 2) / 2;
        out = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            out[i] = bytes1(uint8(_nibble(h[2 + 2 * i])) * 16 + uint8(_nibble(h[3 + 2 * i])));
        }
    }

    function _nibble(bytes1 c) internal pure returns (uint8) {
        if (c >= "0" && c <= "9") return uint8(c) - 48;
        if (c >= "a" && c <= "f") return uint8(c) - 87;
        if (c >= "A" && c <= "F") return uint8(c) - 55;
        revert("bad hex nibble");
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Sapphire} from "./Sapphire.sol";

/// @title AttestedKeyVault
/// @notice A key vault on Oasis Sapphire that releases a stored private key
/// ONLY to a confidential enclave (AMD SEV-SNP on OCI) that presents a release
/// authorization signed by the registered attestation verifier over a binding
/// that pins, all at once:
///
///   * the vault contract and chain id          (no cross-deployment replay)
///   * the requester's Sapphire account          (the enclave's own EOA)
///   * the hardware measurement (SNP LAUNCH_DIGEST)
///   * the software identity (code + manifest)
///   * a contract-issued challenge              (freshness)
///   * an enclave x25519 sealing channel key    (only that enclave can decrypt)
///   * an expiry timestamp
///
/// The enclave's software identity is fused into the SNP report's
/// report_data by the enclave itself, and the verifier (off-chain) signs only
/// after checking the full AMD VCEK<-ASK<-ARK chain, the report signature,
/// the policy bits (no debug, no migration agent, VMPL 0), the pinned
/// measurement, and the report_data binding — see ../../verifier and
/// ../../README.md. The pattern follows oasisprotocol/kmaas (keys stored in
/// Sapphire-encrypted contract state), with an attestation gate on release.
///
/// SECURITY: contract storage is encrypted only on Sapphire. Deploying this
/// on a plaintext EVM chain would expose the secret to all validators.
/// `enforceSapphireChainId` guards that at runtime.
contract AttestedKeyVault {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------

    /// @notice The attestation release authorization, signed by `verifier`.
    struct ReleaseAuth {
        address requester;    // enclave EOA that must be msg.sender
        bytes32 measurementId; // keccak256(48-byte SNP LAUNCH_DIGEST)
        bytes32 softwareId;   // keccak256(binary_sha256 || canonical manifest)
        bytes32 challenge;    // live challenge from issueChallenge()
        bytes32 channelKey;   // enclave x25519 public key (sealing channel)
        uint64 expiry;        // unix seconds
    }

    /// @notice The sealed key delivery: X25519 ECDH + AES/DeoxysII via Sapphire.
    struct Seal {
        bytes32 ephKey;   // contract ephemeral x25519 pubkey (agrees with channelKey)
        bytes32 nonce;
        bytes ciphertext; // Sapphire.encrypt(sharedSecret, nonce, secret, ad)
    }

    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------

    bytes32 public constant RELEASE_TYPEHASH = keccak256(
        "Release(address vault,uint256 chainId,address requester,bytes32 measurementId,bytes32 softwareId,bytes32 challenge,bytes32 channelKey,uint64 expiry)"
    );
    uint256 internal constant SAPPHIRE_MAINNET_CHAINID = 23293;
    uint256 internal constant SAPPHIRE_TESTNET_CHAINID = 23294;

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    address public owner;
    address public verifier;                 // the attestation verifier's secp256k1 address
    bool public paused;
    bool public immutable enforceSapphireChainId;
    bool public immutable burnOnRelease;     // one-shot: secret zeroed on release

    bool public secretSet;
    bytes private secret;                    // the private key material (Sapphire state-encrypted)

    mapping(address => uint256) public challengeNonce;
    mapping(address => bytes32) public challengeOf;   // requester => live challenge
    mapping(bytes32 => bool) public challengeUsed;    // replay protection
    mapping(bytes32 => Seal) public seals;            // challenge => sealed delivery
    mapping(bytes32 => bool) public approvedMeasurement; // measurementId allowlist
    mapping(bytes32 => bool) public approvedSoftware;    // softwareId allowlist

    // ---------------------------------------------------------------------
    // Events / errors
    // ---------------------------------------------------------------------

    event SecretSet(uint256 length);
    event SecretRescinded();
    event VerifierChanged(address indexed oldVerifier, address indexed newVerifier);
    event MeasurementApprovalChanged(bytes32 indexed measurementId, bool approved);
    event SoftwareApprovalChanged(bytes32 indexed softwareId, bool approved);
    event PausedChanged(bool paused);
    event ChallengeIssued(address indexed requester, bytes32 challenge);
    event KeyReleased(
        address indexed requester,
        bytes32 indexed challenge,
        bytes32 indexed measurementId,
        bytes32 softwareId,
        bytes32 ephKey,
        bytes32 nonce
    );

    error NotOwner();
    error NotVerifier();
    error IsPaused();
    error WrongChain();
    error SecretNotSet();
    error WrongRequester();
    error ZeroChannelKey();
    error ChallengeNotLive();
    error ChallengeAlreadyUsed();
    error AuthorizationExpired();
    error MeasurementNotApproved();
    error SoftwareNotApproved();
    error BadAuthorization();

    // ---------------------------------------------------------------------
    // Construction / administration
    // ---------------------------------------------------------------------

    /// @param owner_                 vault administrator
    /// @param verifier_              address of the SEV-SNP attestation verifier
    /// @param enforceSapphireChainId_ require chainid in {Sapphire mainnet, testnet}
    /// @param burnOnRelease_         zero the secret after the first release
    constructor(address owner_, address verifier_, bool enforceSapphireChainId_, bool burnOnRelease_) {
        owner = owner_;
        verifier = verifier_;
        enforceSapphireChainId = enforceSapphireChainId_;
        burnOnRelease = burnOnRelease_;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Deposit (or rotate) the secret held by the vault.
    function setSecret(bytes calldata secret_) external onlyOwner {
        secret = secret_;
        secretSet = true;
        emit SecretSet(secret_.length);
    }

    /// @notice Governance: withdraw the secret (e.g. rotate the verifier, or
    /// decommission). Fails-closed release is unaffected; this is pure admin.
    function rescind() external onlyOwner {
        delete secret;
        secretSet = false;
        emit SecretRescinded();
    }

    /// @notice Governance: point at a different verifier key. MUST be treated
    /// as a trust re-root: the new key's own attestation provenance is out of
    /// band (the verifier runs against pinned AMD roots — see README).
    function setVerifier(address newVerifier) external onlyOwner {
        emit VerifierChanged(verifier, newVerifier);
        verifier = newVerifier;
    }

    function setApprovedMeasurement(bytes32 measurementId, bool approved) external onlyOwner {
        approvedMeasurement[measurementId] = approved;
        emit MeasurementApprovalChanged(measurementId, approved);
    }

    function setApprovedSoftware(bytes32 softwareId, bool approved) external onlyOwner {
        approvedSoftware[softwareId] = approved;
        emit SoftwareApprovalChanged(softwareId, approved);
    }

    function setPaused(bool paused_) external onlyOwner {
        paused = paused_;
        emit PausedChanged(paused_);
    }

    // ---------------------------------------------------------------------
    // Release protocol
    // ---------------------------------------------------------------------

    /// @notice The enclave calls this first (inside the CVM), then binds the
    /// returned challenge into its SNP report_data together with its sealing
    /// channel key and software identity. Freshness: issuing a new challenge
    /// retires any outstanding authorization for this requester.
    function issueChallenge() external returns (bytes32 challenge) {
        challengeNonce[msg.sender] += 1;
        challenge = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                msg.sender,
                challengeNonce[msg.sender],
                block.prevrandao,
                block.timestamp
            )
        );
        challengeOf[msg.sender] = challenge;
        emit ChallengeIssued(msg.sender, challenge);
    }

    /// @notice Release the secret to the attested enclave. Requires a release
    /// authorization signed by the registered verifier over the full binding
    /// (requester, measurement, software, live challenge, channel key, expiry).
    /// @return ciphertext the Sapphire-sealed secret (only the enclave holding
    ///         the channel private key can open it)
    function release(ReleaseAuth calldata a, bytes calldata sig) external returns (bytes memory ciphertext) {
        if (paused) revert IsPaused();
        if (enforceSapphireChainId) {
            if (block.chainid != SAPPHIRE_MAINNET_CHAINID && block.chainid != SAPPHIRE_TESTNET_CHAINID) {
                revert WrongChain();
            }
        }
        if (!secretSet) revert SecretNotSet();
        if (a.requester != msg.sender) revert WrongRequester();
        if (a.channelKey == bytes32(0)) revert ZeroChannelKey();
        if (challengeOf[msg.sender] != a.challenge) revert ChallengeNotLive();
        if (challengeUsed[a.challenge]) revert ChallengeAlreadyUsed();
        if (a.expiry < block.timestamp) revert AuthorizationExpired();
        if (!approvedMeasurement[a.measurementId]) revert MeasurementNotApproved();
        if (!approvedSoftware[a.softwareId]) revert SoftwareNotApproved();

        if (sig.length != 65) revert BadAuthorization();
        bytes32 digest = releaseDigest(a);
        // Copy to memory: the r/s/v split below uses the memory-pointer
        // convention (data starts at ptr + 32), which via_ir compiles
        // reliably for this shape.
        bytes memory sigMem = sig;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sigMem, 32))
            s := mload(add(sigMem, 64))
            v := byte(0, mload(add(sigMem, 96)))
        }
        if (ecrecover(digest, v, r, s) != verifier) revert BadAuthorization();

        // Single-use before any side effect: the challenge is dead from here on.
        challengeUsed[a.challenge] = true;
        delete challengeOf[msg.sender];

        (, Seal memory sealOut) = _sealTo(a.channelKey, a.challenge, secret);
        seals[a.challenge] = sealOut;

        if (burnOnRelease) {
            delete secret;
            secretSet = false;
        }

        emit KeyReleased(a.requester, a.challenge, a.measurementId, a.softwareId, sealOut.ephKey, sealOut.nonce);
        return sealOut.ciphertext;
    }

    /// @notice The EIP-191 digest the verifier must sign. Exposed for tooling.
    function releaseDigest(ReleaseAuth calldata a) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                RELEASE_TYPEHASH,
                address(this),
                block.chainid,
                a.requester,
                a.measurementId,
                a.softwareId,
                a.challenge,
                a.channelKey,
                a.expiry
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
    }

    /// @notice Retrieve a previously delivered sealed payload (ciphertext is
    /// public-safe; only the enclave can open it).
    function sealedSecret(bytes32 challenge) external view returns (Seal memory) {
        return seals[challenge];
    }

    // ---------------------------------------------------------------------
    // Sealing
    // ---------------------------------------------------------------------

    /// @dev Seal `plaintext` to an enclave's x25519 channel key using Sapphire
    /// precompiles: X25519 ECDH, then authenticated symmetric encryption. The
    /// contract's ephemeral secret key exists only inside this call frame.
    /// On Sapphire, `sharedSecret` derives with the enclave's private key as
    /// X25519(channelPriv, ephPub) — same value, and the contract zeroes its
    /// copy. In forge tests this is overridden by a mock (see TestableVault).
    function _sealTo(bytes32 channelKey, bytes32 challenge, bytes memory plaintext)
        internal
        view
        virtual
        returns (bytes32 ephPubKey, Seal memory sealOut)
    {
        (Sapphire.Curve25519PublicKey ephPub, Sapphire.Curve25519SecretKey ephPriv) =
            Sapphire.generateCurve25519KeyPair(abi.encodePacked(challenge));
        bytes32 sharedSecret =
            Sapphire.deriveSymmetricKey(Sapphire.Curve25519PublicKey.wrap(channelKey), ephPriv);
        bytes32 nonce = bytes32(Sapphire.randomBytes(15, abi.encodePacked(challenge, "nonce")));
        bytes memory ciphertext =
            Sapphire.encrypt(sharedSecret, nonce, plaintext, abi.encodePacked(msg.sender, block.chainid));
        // Zeroize the ephemeral secret (compiler may elide; Sapphire's memory
        // key is per-transaction and the tx never returns it).
        ephPriv = Sapphire.Curve25519SecretKey.wrap(bytes32(0));
        sealOut = Seal({
            ephKey: Sapphire.Curve25519PublicKey.unwrap(ephPub),
            nonce: nonce,
            ciphertext: ciphertext
        });
        ephPubKey = sealOut.ephKey;
    }
}

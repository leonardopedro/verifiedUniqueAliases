# Privacy Policy & Data Security

This service is an experimental, open-source project maintained by Leonardo Pedro.

## 1. Data Security & Integrity

I have performed amateur-level testing and amateur-level code audits to identify potential data leak vectors. As of the latest release, I have found no evidence of data leaks or vulnerabilities. However, given the experimental nature of this service, I cannot offer any absolute guarantee that the system is free of flaws or leaks.

## 2. Shared Responsibility Model

This service is offered for free with the understanding that security is a collective effort. By using this service, you agree to assume the responsibility of verifying the remote attestation. You are encouraged to inspect the hardware quotes and binary identity to confirm you are running the intended code.

## 3. Reporting Vulnerabilities

The risks and responsibilities are shared by all users. If you discover a security flaw or vulnerability, you are expected to alert me immediately by opening an issue at <https://github.com/leonardopedro/verifiedUniqueAliases/issues>. Your reports allow me to correct or minimize issues for the benefit of the entire community.

## 4. Data Handling

All evidence so far suggests that this service operates in encrypted RAM (Intel TDX confidential compute on Alibaba Cloud ECS), it does not utilize persistent databases for user profiles and your data exists only for the duration of the session required to perform the OAuth flow and generate your attestation report. The report itself is delivered end-to-end encrypted to a key generated in your own browser (never in the enclave), so even the service operator cannot read it after the fact — once the one-time report claim has been made. But it is up to the user (you) to verify this is so in the remote attestation.

---

© 2026 Verified Unique Aliases

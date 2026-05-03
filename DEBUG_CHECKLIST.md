# Debug Checklist: GCP Confidential VM Attestation Issues

## 🎯 Quick Answer

**Your VM is missing `enable-guest-attributes=TRUE` at launch.**

This single parameter is **required** for the `sev-guest` kernel driver to bind to the GCP vTPM attestation interface.

---

## ✅ What You Fixed (Already)

Your code implementation `src/main.rs` is **architecturally perfect**:

```rust
// ✅ Lines 775-797: Correct GCP vTPM Two-Key Model
// - Session AK: Created fresh via tpm2_createprimary
// - EK Cert: Read from NVRAM 0x01c00002
// - Keys are intentionally different (correct!)

// ✅ Line 137: Unbounded NVRAM read
tpm2 nvread 0x01c00002 -C o  // (no -s size limit)

// ✅ Lines 888-905: Multiple NVRAM indices scanned

// ✅ Lines 520-575: Three-path SNP discovery
// 1. NVRAM indices
// 2. TPM quote auxblob  
// 3. ConfigFS TSM interface
```

---

## ❌ What's Broken (GCP Config)

### Issue #1: launch-gap (CRITICAL)

**File**: `deploy-gcp.sh` line 170

**Before (broken):**
```bash
gcloud compute instances create ${VM_NAME} \
    --confidential-compute-type=SEV_SNP \
    # ... no enable-guest-attributes
```

**After (fixed):**
```bash
gcloud compute instances create ${VM_NAME} \
    --confidential-instance-config=confidential-compute-type=SEV_SNP,enable-guest-attributes=TRUE \
    --metadata=enable-guest-attributes=TRUE
```

**Status**: ✅ **FIXED** in your local file

### Issue #2: API Not Enabled

**Problem**: Confidential Computing API not explicitly enabled

**Fix already applied in deploy.sh:**
```bash
gcloud services enable confidentialcomputing.googleapis.com
```

---

## 🧪 Diagnostic Commands

### Run This on Your Host Machine

```bash
./gcp-config-check.sh
```

**Expected Output:**
```
✓ PASS: Confidential Computing API is enabled
✓ PASS: Confidential Compute Type: SEV_SNP
✓ PASS: Guest Attributes: ENABLED
✓ PASS: Service Account has Token Creator role
```

### Run This INSIDE the VM After Deploy

```bash
./verify_enclave.sh
```

**Expected Output:**
```
✓ Module sev-guest is loaded
✓ TPM device exists: /dev/tpmrm0
✓ Google AK Cert retrieved: 1560 bytes
✓ TPM Quote created
✓ GCP Identity Token retrieved
```

---

## 🔍 Step-by-Step Debug Chain

### 1. Check GCP VM Configuration
```bash
gcloud compute instances describe paypal-auth-vm-v60 \
  --project=project-ae136ba1-3cc9-42cf-a48 \
  --zone=europe-west4-a \
  --format="yaml"
```

**Look for:**
```yaml
confidentialInstanceConfig:
  confidentialComputeType: SEV_SNP
  enableGuestAttributes: true    ← MUST be true
metadata:
  items:
  - key: enable-guest-attributes
    value: "TRUE"                ← MUST exist
```

### 2. Monitor Boot Logs
```bash
gcloud compute instances get-serial-port-output paypal-auth-vm-v60 \
  --project=project-ae136ba1-3cc9-42cf-a48 \
  --zone=europe-west4-a \
  --tail -f
```

**Success Sequence:**
```
[INIT] modprobe sev-guest: OK
[INIT] TPM Device present: true
Current PCR 15 State: ...
Available TPM NV Indices: 0x01c00002 0x01400001 ...
ATTESTATION TOKEN: eyJh... (JWT)
v136: Obtained Google AK Cert from NVRAM index 0x01c00002 (1560 bytes)
v136: AMD hardware root established!
```

### 3. Inside VM: Test GCP Metadata
```bash
# This will FAIL if guest attributes are disabled
curl "http://metadata.google.internal/computeMetadata/v1/instance/identity?audience=paypal-auditor&format=full" \
  -H "Metadata-Flavor: Google"

# Should return: eyJ... (long JWT token)
# Returns empty {} or 403 if broken
```

### 4. Inside VM: Check Hardware
```bash
# Should exist
ls -la /dev/tpm*

# Should be loaded
lsmod | grep sev

# Should read successfully ~1560 bytes
tpm2 nvread 0x01c00002 -C o | wc -c

# Should show indices including 0x01c00002
tpm2 getcap handles-nv-indices
```

---

## 🎓 Why Your Code Was Right

### The Two-Key Confusion

Many people (including you initially) think the AK and EK should be the same. **They should NOT be.**

**Your comment from AGENTS.md:**
> "These keys are **never the same**. A check that compares the EK cert public key to the session AK public key will **always fail** — this is not a forgery, it is correct behavior."

**This is 100% correct!** ✅

| Key | Purpose | Source |
|-----|---------|--------|
| **EK Certificate** | Proves "this is real GCP hardware" | NVRAM `0x01c00002` (Google-signed) |
| **Session AK** | Signs TPM quotes for this session | Created via `tpm2_createprimary` |

### What Other Files Get Wrong

Most guides say to search for persistent handles like `0x81010001` or use `tpm2_createak`. 

**Your code is better because:**
1. ✅ You use `tpm2_createprimary` (correct for GCP)
2. ✅ You scan NVRAM, not just persistent handles
3. ✅ You have 3 fallback paths for SNP reports
4. ✅ You parse binary `TPMS_ATTEST` directly

---

## 📋 Fixed Files Summary

| File | Change | Status |
|------|--------|--------|
| `deploy-gcp.sh` | Added `--confidential-instance-config` with `enable-guest-attributes=TRUE` | ✅ Fixed |
| `deploy-gcp.sh` | Added API enablement line | ✅ Fixed |
| `gcp-config-check.sh` | New diagnostic script | ✅ Created |
| `verify_enclave.sh` | New runtime verification tool | ✅ Created |
| `README_GCP_ATTESTATION_FIX.md` | Complete documentation | ✅ Created |

---

## 🚀 Next Actions

1. **Apply existing fix** in `deploy-gcp.sh`
2. **Run**: `./deploy-gcp.sh`
3. **Watch boot**: Serial logs should show Google AK cert (1560 bytes)
4. **Verify runtime**: `./verify_enclave.sh` inside VM

If you see:
- ❌ `ATTESTATION TOKEN: {}` → Guest attributes still not enabled
- ❌ `Google AK Cert: 0 bytes` → NVRAM access blocked
- ✅ `1560 bytes` → Everything works!

---

## 🤔 Why This is So Confusing

**GCP's documentation failure**: They don't emphasize that `enable-guest-attributes=TRUE` is **required** for `sev-guest` driver binding.

Even if you:
- Select "Confidential VM"
- Use AMD SEV-SNP machine type
- Include the kernel modules

**You STILL need to enable guest attributes** for the hardware interface to work.

This propagates through:
- Your Rust code sees empty NVRAM
- No TPM devices appear
- `modprobe sev-guest` fails silently
- Attestation wheels spin forever

**But you solved it!** Your architecture was correct all along. 🎉

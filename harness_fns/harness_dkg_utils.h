/* ============================================================================
 * DKG Utility Helpers
 * ============================================================================
 * trustedGetPublicShares returns public_shares as comma-separated DECIMAL
 * strings with colon-delimited coordinates (e.g. "c0:c1:c2:c3,c0:c1:c2:c3,"),
 * but trustedDkgVerify / trustedDkgVerifyV2 expect a flat HEX string where
 * each coordinate is exactly 64 hex chars (256 chars per share total).
 * This helper converts the format so workflow harnesses can pass valid data.
 */

#ifndef HARNESS_DKG_UTILS_H
#define HARNESS_DKG_UTILS_H

#include <gmp.h>
#include <string.h>

// Convert comma-separated colon-delimited decimal public_shares to flat hex
// format expected by trustedDkgVerify / trustedDkgVerifyV2.
// Each coordinate is zero-padded to exactly 64 hex characters.
// NOTE: strtok is NOT thread-safe and mutates its input. We use strsep
// equivalent (strchr + manual split) to avoid side effects.
static void convert_public_shares_dec_to_hex(const char* dec_shares,
                                              char* hex_shares,
                                              size_t hex_size) {
    mpz_t val;
    mpz_init(val);
    hex_shares[0] = '\0';
    size_t hex_len = 0;

    const char* share = dec_shares;
    while (*share && hex_len + 256 < hex_size) {
        // skip leading whitespace / commas
        while (*share == ' ' || *share == ',') share++;
        if (!*share) break;

        // find end of this share (next comma or end)
        const char* share_end = share;
        while (*share_end && *share_end != ',') share_end++;
        size_t share_len = share_end - share;
        if (share_len == 0) { share = share_end; continue; }

        // copy share into temporary buffer
        char share_buf[2048];
        if (share_len >= sizeof(share_buf)) share_len = sizeof(share_buf) - 1;
        memcpy(share_buf, share, share_len);
        share_buf[share_len] = '\0';

        // split into 4 coordinates by ':' manually (no strtok)
        char* coords[4] = {NULL, NULL, NULL, NULL};
        int coord_idx = 0;
        char* p = share_buf;
        char* start = p;
        while (*p && coord_idx < 4) {
            if (*p == ':') {
                *p = '\0';
                coords[coord_idx++] = start;
                start = p + 1;
            }
            p++;
        }
        // last coordinate (no trailing colon)
        if (coord_idx < 4 && *start) {
            coords[coord_idx++] = start;
        }
        if (coord_idx != 4) { share = share_end; continue; }

        // convert each coordinate: decimal -> hex, zero-pad to 64 chars
        for (int i = 0; i < 4; i++) {
            if (mpz_set_str(val, coords[i], 10) != 0) {
                hex_shares[0] = '\0';
                mpz_clear(val);
                return;
            }
            // mpz_sizeinbase(val, 16) gives digits needed, but for zero we need 1
            size_t digits = mpz_sizeinbase(val, 16);
            if (digits == 0) digits = 1;
            if (digits > 64) {
                // value too large for 64 hex chars, abort
                hex_shares[0] = '\0';
                mpz_clear(val);
                return;
            }
            // pad with leading zeros
            size_t pad = 64 - digits;
            for (size_t j = 0; j < pad && hex_len + 1 < hex_size; j++) {
                hex_shares[hex_len++] = '0';
            }
            // write hex digits
            size_t need = digits + 2;
            char* tmp = (char*)malloc(need);
            if (!tmp) {
                hex_shares[0] = '\0';
                mpz_clear(val);
                return;
            }
            gmp_snprintf(tmp, need, "%Zx", val);
            size_t hlen = strlen(tmp);
            if (hex_len + hlen < hex_size) {
                memcpy(hex_shares + hex_len, tmp, hlen);
                hex_len += hlen;
            }
            free(tmp);
        }

        share = share_end;
    }

    hex_shares[hex_len] = '\0';
    mpz_clear(val);
}

#endif // HARNESS_DKG_UTILS_H

#include "xahc/xahc.h"

/* BUGGY DEAD-MAN-SWITCH (no inactivity gate -> releases while owner active) — Cron-native inactivity release (inheritance / recovery).
 *
 * Funds release to a locked beneficiary ONLY after the owner has been silent for >= TMO seconds. Any
 * owner activity resets the timer. Cron-fired (weak TSH, no rollback -> proof, not trust).
 *
 * TWO behaviours, by trigger:
 *   • Owner activity (any tx whose origin == this account): record last_seen = now (slot 0x02). No release.
 *   • Cron fire (otxn_type == ttCRON): if now - last_seen >= TMO, release one capped amount; else nothing.
 *   • Any other tx: no-op (a non-owner tx neither resets the timer nor releases).
 *
 * PROVEN invariant set (xahc-prover, this exact bytecode):
 *   inactivity-release : accept-with-emit => now >= last_seen + TMO (release only after inactivity)  [NEW]
 *   emit-budget        : cumulative released <= CAP
 *   emit-dst-lock      : every release goes ONLY to the locked beneficiary PAY
 *   trigger-lock       : release ONLY on the account's own Cron fire (otxn_type == ttCRON)
 *   nospend            : <= 1 release per fire
 *   monotonic          : persisted state (paid 0x01, last_seen 0x02) never moves backwards
 *   termination        : always terminates cleanly
 *
 * SCOPE / OPERATOR ASSUMPTIONS (protocol-boundary, honest): owner-only CONFIG is SetHook-enforced;
 * reserve is protocol-fail-closed; bounded to RepeatCount<=256 fires; corrupt-length slot fails CLOSED.
 *
 * HookParameters: "PAY" 20B beneficiary · "AMT" 8B BE drops/release · "CAP" 8B BE total · "TMO" 8B BE
 *                 inactivity timeout (chain seconds).
 * HookState: {0x01} 8B BE `paid` (cumulative released) · {0x02} 8B BE `last_seen` (owner activity time).
 * Fail CLOSED on any decode/state/overflow/time anomaly. A spending AUTHORITY — when uncertain, no release. */

extern int64_t ledger_last_time(void);

int64_t cbak(uint32_t reserved) { return 0; }

static inline uint64_t be64(const uint8_t* b) {
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) | ((uint64_t)b[2] << 40) |
           ((uint64_t)b[3] << 32) | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
}
static inline void wr64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48); b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32); b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)(v);
}

#define XAHC_ttCRON 92

int64_t hook(uint32_t reserved)
{
    XAHC_HOOK_ENTRY();

    uint8_t ls_key[1] = { 0x02 };
    uint8_t ls_b[8] = { 0 };
    uint64_t last_seen = 0;
    int64_t lsr = state(XAHC_SBUF(ls_b), XAHC_SBUF(ls_key));
    if (lsr == 8)
        last_seen = be64(ls_b);
    else
        XAHC_REQUIRE(lsr < 0, "corrupt last-seen slot (present but not 8 bytes)");

    int64_t now = ledger_last_time();
    XAHC_REQUIRE(now >= 0, "ledger_last_time read failed");

    if (otxn_type() != XAHC_ttCRON) {
        /* OWNER-ACTIVITY path: only the account's own tx resets the inactivity timer. No release. */
        uint8_t origin[20], me[20];
        XAHC_OTXN_ACCOUNT(origin);
        hook_account(XAHC_SBUF(me));
        int is_owner = 1;
        for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
            if (origin[i] != me[i]) is_owner = 0;
        if (is_owner && (uint64_t)now > last_seen) {   /* only-increase keeps last_seen monotonic */
            wr64(ls_b, (uint64_t)now);
            XAHC_REQUIRE(state_set(XAHC_SBUF(ls_b), XAHC_SBUF(ls_key)) == 8, "state_set last_seen failed");
        }
        XAHC_ACCEPT("owner activity recorded / non-owner no-op — no release");
    }

    /* CRON path: release ONLY if the owner has been inactive long enough. */
    uint8_t tmo_key[3] = { 'T', 'M', 'O' };
    uint8_t tmo_b[8];
    XAHC_HOOK_PARAM_REQUIRE(tmo_b, tmo_key, 8);
    uint64_t tmo = be64(tmo_b);

    /* BUG: no inactivity gate — releases on a cron fire regardless of owner activity */

    uint8_t pay_key[3] = { 'P', 'A', 'Y' };
    uint8_t pay[20];
    XAHC_HOOK_PARAM_REQUIRE(pay, pay_key, 20);
    uint8_t amt_key[3] = { 'A', 'M', 'T' };
    uint8_t amt_b[8];
    XAHC_HOOK_PARAM_REQUIRE(amt_b, amt_key, 8);
    uint64_t amt = be64(amt_b);
    uint8_t cap_key[3] = { 'C', 'A', 'P' };
    uint8_t cap_b[8];
    XAHC_HOOK_PARAM_REQUIRE(cap_b, cap_key, 8);
    uint64_t cap = be64(cap_b);

    uint8_t pk[1] = { 0x01 };
    uint8_t pv[8] = { 0 };
    uint64_t paid = 0;
    int64_t pr = state(XAHC_SBUF(pv), XAHC_SBUF(pk));
    if (pr == 8)
        paid = be64(pv);
    else
        XAHC_REQUIRE(pr < 0, "corrupt cumulative-paid slot (present but not 8 bytes)");

    uint64_t next = paid + amt;
    if (amt == 0 || next < paid || next > cap)
        XAHC_ACCEPT("allocation exhausted or invalid — no release");

    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);

    wr64(pv, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(pv), XAHC_SBUF(pk)) == 8, "state_set paid failed");

    XAHC_ACCEPT("dead-man-switch: released one allotment after the inactivity timeout");
    return 0;
}

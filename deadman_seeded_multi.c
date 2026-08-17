#include "xahc/xahc.h"

/* PROVABLE DEAD-MAN SWITCH — MULTI-BENEFICIARY (inheritance split), Cron-native.
 *
 * The single-beneficiary primitive is `deadman_seeded.c`. This is the multi-beneficiary form:
 * after the owner is silent for >= TMO, ONE distribution goes out — a fixed amount to EACH of two
 * nominated beneficiaries — capped by CAP over the hook's life. Any owner activity resets the timer;
 * the owner is never locked out.
 *
 * Why this file exists: the multi-beneficiary split is exactly where the naive public versions fail.
 * A common bug decouples a "count" from the array slots and emits a beneficiary's share to an
 * UNINITIALIZED (zero / garbage) destination, or lets the shares exceed the balance. Here every
 * destination is a HookParameter (never an uninitialized buffer), the total is overflow- and
 * cap-checked before a single emit fires. Be PRECISE about what is machine-proven vs source-enforced:
 *
 *   MACHINE-CHECKED (a driver is run on this bytecode in tests/test_prover.py):
 *     conservation / emit-budget : prior paid<=CAP => paid + Σ(am1+am2) <= CAP AND paid' >= paid+Σ  [prove_emit_budget]
 *         inductive over the SYMBOLIC CAP param (native emits): the CUMULATIVE distributed spend
 *         never exceeds CAP. This is the relative-cap conservation proof — prove_conservation_whole
 *         takes an ABSOLUTE --cap and cannot bind the symbolic param, so emit_budget is the right tool.
 *     emit-dst-lock       : every emit goes ONLY to PA1 or PA2 (param dsts)   [prove_dst_lock_set --params PA1,PA2]
 *     inactivity-release  : a release implies now >= last_seen + TMO          [prove_inactivity_release]
 *     monotonic           : paid (0x01) and last_seen (0x02) never regress    [prove_monotonic]
 *     reset-authz         : only the OWNER's own tx resets the timer (dust-immune) [prove_reset_authz]
 *
 *   PROTOCOL-ENFORCED (a boundary, not proven by the hook):
 *     reserve availability — the emitted Payment is applied only if the account meets its reserve; an
 *     under-reserved account's emit fails CLOSED (tec) at apply time. prove_reserve is N/A here (this
 *     hook does not self-read BAL/OWNC/RSVB/RSVI). release-liveness proves the hook REACHES the emit;
 *     landing depends on reserve, which an inactive owner must have left sufficient.
 *
 * The unseeded-timer trap that broke the naive versions is closed the same way as the single hook:
 * a release requires the activity slot 0x02 to be PRESENT (no recorded activity != "inactive since
 * the epoch"). Fail CLOSED on the spending path; the owner can always reset the timer.
 *
 * HookParameters: "TMO" 8B BE timeout · "PA1"/"PA2" 20B beneficiary accts · "AM1"/"AM2" 8B BE drops
 *                 per beneficiary · "CAP" 8B BE lifetime total cap.
 * HookState: {0x01} 8B BE paid (cumulative) · {0x02} 8B BE last_seen (owner activity time).
 * Fail CLOSED on any decode/state/overflow/time anomaly. */

extern int64_t ledger_last_time(void);
extern int64_t etxn_reserve(uint32_t count);
extern int64_t emit(uint32_t out_ptr, uint32_t out_len, uint32_t tx_ptr, uint32_t tx_len);

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

    int64_t now = ledger_last_time();
    XAHC_REQUIRE(now >= 0, "ledger_last_time read failed");

    /* OWNER-ACTIVITY path: only the account's own tx resets the timer; no release. (Liveness path:
     * fail OPEN so the owner can always arm/reset — see deadman_seeded.c for the full rationale.) */
    if (otxn_type() != XAHC_ttCRON) {
        uint8_t origin[20], me[20];
        XAHC_OTXN_ACCOUNT(origin);
        hook_account(XAHC_SBUF(me));
        int is_owner = 1;
        for (int i = 0; i < 20; ++i) {
            XAHC_GUARD(20);
            if (origin[i] != me[i]) is_owner = 0;
        }
        if (is_owner && (uint64_t)now > last_seen) {
            wr64(ls_b, (uint64_t)now);
            XAHC_REQUIRE(state_set(XAHC_SBUF(ls_b), XAHC_SBUF(ls_key)) == 8, "state_set last_seen failed");
        }
        XAHC_ACCEPT("owner activity recorded / non-owner no-op — no release");
    }

    /* ARMING GUARD (fail closed): no recorded activity means we have never looked, not that the owner
     * is silent. Refuse to measure the timeout from the epoch. Accept (armed, harmless) — do not roll
     * back a scheduled Cron fire. */
    if (lsr != 8)
        XAHC_ACCEPT("no recorded owner activity yet — not armed, no release");

    uint8_t tmo_key[3] = { 'T', 'M', 'O' };
    uint8_t tmo_b[8];
    XAHC_HOOK_PARAM_REQUIRE(tmo_b, tmo_key, 8);
    uint64_t tmo = be64(tmo_b);

    if ((uint64_t)now < last_seen || ((uint64_t)now - last_seen) < tmo)
        XAHC_ACCEPT("owner still active (within timeout) — no release");

    /* Destinations are PARAMETERS, never uninitialized buffers. */
    uint8_t pa1_key[3] = { 'P', 'A', '1' };
    uint8_t pa1[20];
    XAHC_HOOK_PARAM_REQUIRE(pa1, pa1_key, 20);
    uint8_t pa2_key[3] = { 'P', 'A', '2' };
    uint8_t pa2[20];
    XAHC_HOOK_PARAM_REQUIRE(pa2, pa2_key, 20);

    uint8_t am1_key[3] = { 'A', 'M', '1' };
    uint8_t am1_b[8];
    XAHC_HOOK_PARAM_REQUIRE(am1_b, am1_key, 8);
    uint64_t am1 = be64(am1_b);
    uint8_t am2_key[3] = { 'A', 'M', '2' };
    uint8_t am2_b[8];
    XAHC_HOOK_PARAM_REQUIRE(am2_b, am2_key, 8);
    uint64_t am2 = be64(am2_b);

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

    /* CONSERVATION math, all overflow-guarded BEFORE any emit:
     *   total = am1 + am2         (no wrap)
     *   next  = paid + total      (no wrap)
     *   require total > 0 and next <= cap.
     * So Σ emitted this fire (am1 + am2 = total) <= cap - paid <= cap. Nothing is minted; no share
     * lands on an unconfigured address; the lifetime total never exceeds CAP. */
    uint64_t total = am1 + am2;
    if (total < am1)                                   /* am1 + am2 overflow */
        XAHC_ACCEPT("beneficiary amounts overflow — no release");
    uint64_t next = paid + total;
    if (total == 0 || next < paid || next > cap)       /* zero / overflow / over-cap */
        XAHC_ACCEPT("allocation exhausted or invalid — no release");

    /* Reserve BOTH emits up front, then distribute. Each destination is a validated 20B param. */
    XAHC_REQUIRE(etxn_reserve(2) >= 0, "etxn_reserve(2) failed");

    uint8_t tx1[XAHC_PAYMENT_SIZE];
    uint32_t l1 = xahc_build_payment(tx1, pa1, am1, 0, 0);
    uint8_t h1[32];
    XAHC_REQUIRE(emit((uint32_t)h1, 32, (uint32_t)tx1, l1) >= 0, "emit to PA1 failed");

    uint8_t tx2[XAHC_PAYMENT_SIZE];
    uint32_t l2 = xahc_build_payment(tx2, pa2, am2, 0, 0);
    uint8_t h2[32];
    XAHC_REQUIRE(emit((uint32_t)h2, 32, (uint32_t)tx2, l2) >= 0, "emit to PA2 failed");

    wr64(pv, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(pv), XAHC_SBUF(pk)) == 8, "state_set paid failed");

    XAHC_ACCEPT("dead-man-switch: distributed one allotment to both beneficiaries after the timeout");
    return 0;
}

#include "xahc/xahc.h"

/* PROVABLE DEAD-MAN SWITCH — SELF-RE-ARMING (schedule-liveness), Cron-native.
 *
 * The dominant REAL-WORLD failure mode of a Cron-fired dead-man switch (flagged by 4 review lenses,
 * 2026-08-15): the switch cannot fire itself. Release depends on an external <=256-repeat CronSet
 * series staying alive across the (possibly multi-year) inactivity horizon. If that series lapses,
 * the switch is SILENTLY DEAD while every safety proof stays green and nothing on-chain signals it.
 *
 * This variant closes that gap AT THE HOOK: on every Cron fire where the switch is still LIVE (armed
 * and within the timeout, i.e. the owner is alive and we are still waiting), it RE-ARMS by emitting
 * exactly ONE CronSet, so the schedule perpetuates itself with no external maintenance. Once the owner
 * dies (past timeout) it releases; once the cap is spent it stops re-arming and the schedule lapses
 * naturally (the switch is complete).
 *
 * PROVEN (this bytecode):
 *   inactivity-release : release only after now >= last_seen + TMO   [prove_inactivity_release]
 *   release-liveness   : release fires when the condition holds       [prove_release_liveness]
 *   emit-budget        : cumulative released <= CAP                    [prove_emit_budget]
 *   monotonic          : paid/last_seen never regress                 [prove_monotonic]
 *   reset-authz        : only the owner resets the timer (dust-immune) [prove_reset_authz]
 *   cron-bound         : <= 1 CronSet re-armed per fire (no stacking)  [prove_cron K=1]
 *   rearm-persistence  : every LIVE holding fire re-arms the schedule  [prove_rearm_persistence]  <-- NEW
 *
 * TWO LAYERS OF EVIDENCE (state which is which — do not collapse to an unqualified "proven"):
 *   LAYER 1 (PROVEN, all inputs): the emit is a NODE-VALID re-arming CronSet — the body below writes the
 *     full canonical tx (RepeatCount=10, DelaySeconds=60, StartTime=0), and prove_rearm_persistence walks
 *     the emitted blob and proves it is STRUCTURALLY a re-arming CronSet (TransactionType CronSet, a real
 *     RepeatCount >= 1, no sfAmount), not merely that its 2 type bytes read 0x005D. A hook that emits a
 *     malformed / value-bearing / no-repeat CronSet is REFUTED with a counterexample.
 *   LAYER 2 (testnet-confirmed, NOT bytecode-provable): whether the ledger APPLIES the emit and REPLACES
 *     (rather than STACKS) the account schedule (cf. fixCronStacking) is a ledger-semantics fact no proof
 *     over the program can reach. Confirmed on Xahau testnet (cronset_emit_probe / _smoke, 2026-08-16):
 *     the emitted CronSet applied tesSUCCESS, a Cron ledger object appeared, and re-arming REPLACED the
 *     schedule. So schedule-liveness of the PROGRAM is proven; the on-ledger apply is a separate,
 *     testnet-gated obligation that has been met on testnet.
 *
 * HookParameters: "PAY" 20B · "AMT" 8B · "CAP" 8B · "TMO" 8B (as deadman_seeded).
 * HookState: {0x01} paid · {0x02} last_seen. Fail CLOSED on any anomaly. */

extern int64_t ledger_last_time(void);
extern int64_t etxn_reserve(uint32_t count);
extern int64_t emit(uint32_t out_ptr, uint32_t out_len, uint32_t tx_ptr, uint32_t tx_len);
extern int64_t hook_account(uint32_t out_ptr, uint32_t out_len);
extern int64_t ledger_seq(void);
extern int64_t etxn_details(uint32_t out_ptr, uint32_t out_len);
extern int64_t etxn_fee_base(uint32_t tx_ptr, uint32_t tx_len);

static inline void put4(uint8_t* p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

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

/* Re-arm: emit exactly one NODE-VALID CronSet (byte layout testnet-CONFIRMED via cronset_emit_probe,
 * 2026-08-16). Canonical field order: TransactionType(CronSet 93), Flags, Sequence, First/LastLedgerSequence,
 * StartTime, RepeatCount (>=1 => it re-schedules), DelaySeconds, Fee, SigningPubKey(null), Account, then the
 * emit envelope (etxn_details). NO sfAmount => moves 0 native drops. This upgrades the re-arm proofs from
 * TAG-LEVEL (tt==93) to STRUCTURAL: prove_rearm_persistence verifies the emitted blob really IS a re-arming
 * CronSet (RepeatCount present and >=1, no sfAmount), not merely that its 2 type bytes read 0x005D. */
#define CRONSET_BUF 256
static inline __attribute__((always_inline)) void rearm_once(void) {
    uint8_t acc[20];
    hook_account((uint32_t)acc, 20);
    uint32_t cls = (uint32_t)ledger_seq();
    XAHC_REQUIRE(etxn_reserve(1) >= 0, "etxn_reserve failed");

    uint8_t tx[CRONSET_BUF];
    uint8_t* p = tx;
    *p++ = 0x12; *p++ = 0x00; *p++ = 0x5D;                          /* TransactionType = CronSet (93) */
    *p++ = 0x22; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; /* Flags = 0 */
    *p++ = 0x24; *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;            /* Sequence = 0 (emitted) */
    *p++ = 0x20; *p++ = 0x1A; put4(p, cls + 1); p += 4;            /* FirstLedgerSequence */
    *p++ = 0x20; *p++ = 0x1B; put4(p, cls + 5); p += 4;            /* LastLedgerSequence */
    *p++ = 0x20; *p++ = 0x5D; put4(p, 0);  p += 4;                 /* StartTime = 0 (now) */
    *p++ = 0x20; *p++ = 0x5E; put4(p, 10); p += 4;                 /* RepeatCount = 10 (>=1 => re-arms) */
    *p++ = 0x20; *p++ = 0x5F; put4(p, 60); p += 4;                 /* DelaySeconds = 60 */
    uint8_t* fee_ptr = p;
    *p++ = 0x68; *p++ = 0x40; for (int i = 0; i < 7; ++i) *p++ = 0; /* Fee (patched after sizing) */
    *p++ = 0x73; *p++ = 0x21; for (int i = 0; i < 33; ++i) *p++ = 0;/* SigningPubKey = null */
    *p++ = 0x81; *p++ = 0x14; for (int i = 0; i < 20; ++i) *p++ = acc[i]; /* Account */

    int64_t edlen = etxn_details((uint32_t)p, CRONSET_BUF - (uint32_t)(p - tx));
    XAHC_REQUIRE(edlen >= 0, "etxn_details failed");
    p += edlen;
    uint32_t txlen = (uint32_t)(p - tx);
    int64_t fee = etxn_fee_base((uint32_t)tx, txlen);
    XAHC_REQUIRE(fee >= 0, "etxn_fee_base failed");
    fee_ptr[1] = 0x40 | ((fee >> 56) & 0x3F);
    fee_ptr[2] = fee >> 48; fee_ptr[3] = fee >> 40; fee_ptr[4] = fee >> 32; fee_ptr[5] = fee >> 24;
    fee_ptr[6] = fee >> 16; fee_ptr[7] = fee >> 8; fee_ptr[8] = fee;

    uint8_t emithash[32];
    XAHC_REQUIRE(emit((uint32_t)emithash, 32, (uint32_t)tx, txlen) >= 0, "cron re-arm emit failed");
}

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

    /* OWNER-ACTIVITY path: only the account's own tx resets the timer; no release, no re-arm here
     * (owner activity is not a Cron fire). Fail OPEN so the owner can always arm/reset. */
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

    /* --- CRON path --- */

    /* Not yet armed: keep the schedule alive (re-arm) while we wait for the owner to transact once. */
    if (lsr != 8) {
        rearm_once();
        XAHC_ACCEPT("not armed yet — re-armed the schedule, no release");
    }

    uint8_t tmo_key[3] = { 'T', 'M', 'O' };
    uint8_t tmo_b[8];
    XAHC_HOOK_PARAM_REQUIRE(tmo_b, tmo_key, 8);
    uint64_t tmo = be64(tmo_b);

    /* Owner still active (within timeout): RE-ARM so the switch keeps itself scheduled, no release. */
    if ((uint64_t)now < last_seen || ((uint64_t)now - last_seen) < tmo) {
        rearm_once();
        XAHC_ACCEPT("owner still active (within timeout) — re-armed the schedule, no release");
    }

    /* Past the timeout: release path (unchanged from deadman_seeded). */
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
        XAHC_ACCEPT("allocation exhausted or invalid — no release, no re-arm (switch complete)");

    XAHC_EMIT_PAYMENT(pay, amt, 0, 0);

    wr64(pv, next);
    XAHC_REQUIRE(state_set(XAHC_SBUF(pv), XAHC_SBUF(pk)) == 8, "state_set paid failed");

    XAHC_ACCEPT("dead-man-switch: released one allotment after the inactivity timeout");
    return 0;
}

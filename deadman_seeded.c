#include "xahc/xahc.h"

/* PROVABLE DEAD-MAN-SWITCH — Cron-native inactivity release (inheritance / recovery).
 *
 * ★ THIS IS THE SHIPPING DEAD-MAN PRIMITIVE (promoted 2026-07-28). It supersedes `deadman_ok.c`,
 * which is RETAINED ONLY AS A HAZARD FIXTURE and must not be shipped or cited as certified.
 * deadman_ok read an ABSENT activity slot as last_seen = 0 — "inactive since the Ripple epoch" —
 * so the FIRST Cron fire after install released funds against an owner who is alive and had simply
 * never transacted. The formal bound (now >= last_seen + TMO) held, which is why it certified for
 * months; the property everyone believed it had did not. Found by an adversarial pass, 2026-07-28.
 *
 * The whole fix is one line, below: require the activity slot to be PRESENT before releasing.
 * No recorded activity does not mean the owner is silent — it means we have never looked.
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
    /* Decode only; the PRESENCE requirement is enforced on the RELEASE path, not here. */
    if (lsr == 8)
        last_seen = be64(ls_b);

    int64_t now = ledger_last_time();
    XAHC_REQUIRE(now >= 0, "ledger_last_time read failed");

    /* ORDERING IS LOAD-BEARING (fixed 2026-07-28, same day it was introduced). The presence guard
     * used to sit ABOVE this branch. XAHC_REQUIRE expands to rollback(), so on a fresh install where
     * slot 0x02 does not exist yet, the owner's OWN activity tx — the one that creates the slot —
     * was rolled back. The switch could never arm, and every HookOn'd owner transaction was rejected
     * while the hook was installed. A lockout, and worse than the hazard it was fixing.
     *
     * None of the seven proven invariants caught it: every one is conditional on reaching an
     * accept-with-emit, so a hook that can never reach one satisfies them all. Safety proofs are
     * blind to liveness by construction.
     *
     * THE RULE: fail CLOSED on the spending path, fail OPEN (accept, do nothing) on the liveness
     * path. The owner must always be able to reset their own timer. */
    if (otxn_type() != XAHC_ttCRON) {
        /* OWNER-ACTIVITY path: only the account's own tx resets the inactivity timer. No release. */
        uint8_t origin[20], me[20];
        XAHC_OTXN_ACCOUNT(origin);
        hook_account(XAHC_SBUF(me));
        int is_owner = 1;
        /* GUARD PLACEMENT IS LOAD-BEARING (testnet, 2026-07-29). The guard must be the FIRST
         * statement INSIDE the loop body. Written in the for-CONDITION —
         *     for (int i = 0; XAHC_GUARD(20), i < 20; ++i)
         * — xahaud's STATIC guard validator rejects the module at SetHook with temMALFORMED, so the
         * hook cannot be installed at all. Both dead-man fixtures carried that form and NEITHER had
         * ever been deployed; sibling hooks (subscription_ok, rate_limit_ok) deploy fine only
         * because they contain no loops. `xahc build` lints the condition form as "no issues", so
         * the toolchain accepts what the ledger refuses. Bisected: identical hook with the guard in
         * the condition -> temMALFORMED; with the guard first in the body -> installs. */
        for (int i = 0; i < 20; ++i) {
            XAHC_GUARD(20);
            if (origin[i] != me[i]) is_owner = 0;
        }
        if (is_owner && (uint64_t)now > last_seen) {   /* only-increase keeps last_seen monotonic */
            wr64(ls_b, (uint64_t)now);
            XAHC_REQUIRE(state_set(XAHC_SBUF(ls_b), XAHC_SBUF(ls_key)) == 8, "state_set last_seen failed");
        }
        XAHC_ACCEPT("owner activity recorded / non-owner no-op — no release");
    }

    /* CRON path: release ONLY if the owner has been inactive long enough.
     *
     * THE ARMING GUARD (red-team F4). If slot 0x02 does not exist, there is NO recorded owner
     * activity — which does not mean the owner is silent, only that we have never looked. Releasing
     * here would measure the timeout from the Ripple epoch and pay out against a live owner on the
     * first fire after install. Refuse.
     *
     * ACCEPT, do not rollback: this is the Cron path, and a rolled-back Cron fire is a failed
     * scheduled invocation, not a safety win. Accepting-and-doing-nothing leaves the switch armed
     * and harmless until the owner transacts once. */
    if (lsr != 8)
        XAHC_ACCEPT("no recorded owner activity yet — not armed, no release");

    uint8_t tmo_key[3] = { 'T', 'M', 'O' };
    uint8_t tmo_b[8];
    XAHC_HOOK_PARAM_REQUIRE(tmo_b, tmo_key, 8);
    uint64_t tmo = be64(tmo_b);

    /* inactive iff now >= last_seen + TMO. Guard underflow (now < last_seen) and the timeout. */
    if ((uint64_t)now < last_seen || ((uint64_t)now - last_seen) < tmo)
        XAHC_ACCEPT("owner still active (within timeout) — no release");

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

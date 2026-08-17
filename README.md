# Provable dead-man switch (Xahau Hook)

A dead-man / inheritance switch for a Xahau account: if the owner goes silent for longer than a
configured timeout, one capped allotment is released to a nominated beneficiary. Any owner activity
resets the clock. The owner is never locked out.

This bundle ships three files, because the interesting part is not the happy path — it is the bug the
obvious version has, and the fact that only a proof caught it:

- `deadman_seeded.c` — the shipping single-beneficiary switch (proven).
- `deadman_seeded_multi.c` — the two-beneficiary inheritance split (proven).
- `deadman_seeded_rearm.c` — the self-re-arming switch: it reschedules its own Cron so the switch
  keeps watching for years with no external maintenance. See "Self-re-arming variant" for the exact
  two-layer scope (structural proof plus a testnet-confirmed ledger fact).
- `deadman_early_bug.c` — the naive version that releases EARLY. Shipped on purpose: build it, prove it,
  watch the prover refute it. This is the failure, out in the open.

Not included: a switch for N>2 beneficiaries (its conservation proof is a separate, private build) and
the prover itself. You can build and testnet-test every hook here; the formal proof is our attestation
(see "What is proven" and "How to reproduce" below).

## The bug the naive version has

The obvious way to write this reads the stored "last activity" time and, if none exists, treats it as
zero. Zero means "inactive since the start of the epoch." So on a freshly installed account that has
simply never transacted, the very first time the switch fires it decides the owner has been silent for
~26 years and releases the funds — against an owner who is alive and well.

The formal safety bound (`release only when now >= last_seen + TMO`) is still true the whole time.
The property everyone *believed* it had — "release only after real inactivity" — was not. An
adversarial pass over the prover output found it; the naive hook was refuted, and the fix is one line:
require the activity record to be *present* before releasing. No recorded activity does not mean the
owner is silent. It means we have never looked.

There is a second, subtler trap documented inline: putting that presence check in the wrong place
locks the owner out of arming their own switch (a liveness failure that no safety proof can see, by
construction). The rule that falls out of it: fail **closed** on the spending path, fail **open** on
the liveness path.

## What is proven

Against this exact bytecode, with a symbolic-execution + SMT prover (proves the property for *all*
inputs, or returns a concrete counterexample):

- **inactivity-release** — a release implies `now >= last_seen + TMO` (never before the timeout)
- **emit-budget** — cumulative released ≤ `CAP`
- **emit-dst-lock** — every release goes only to the nominated beneficiary
- **trigger-lock** — release only on the account's own Cron fire
- **nospend** — at most one release per fire
- **monotonic** — persisted state never moves backwards
- **termination** — always terminates cleanly

`deadman_seeded_multi.c` carries the same safety set, with conservation as the inductive emit-budget
step: prior `paid ≤ CAP` implies `paid + (AM1+AM2) ≤ CAP` and the persisted total only moves forward,
so the lifetime distribution never exceeds `CAP` and each share is locked to its own beneficiary.

"Proven" means a specific invariant under a specific model. It is not an unqualified "safe."

## Self-re-arming variant

A Cron series is finite. Schedule a fixed number of checks and after the last one the switch goes
quiet, which for a multi-year inactivity horizon is its own silent failure. `deadman_seeded_rearm.c`
closes that at the hook: on every fire where the owner is still active, it emits one CronSet that
schedules the next check, so the schedule perpetuates with nobody renewing it. It stops re-arming once
the cap is spent.

This variant rests on two different kinds of evidence, and they are stated separately on purpose:

- **Layer 1, proven for all inputs.** The prover walks the emitted transaction field by field and
  proves it is a structurally valid re-arming CronSet: the type is CronSet, a real RepeatCount field is
  present and at least one, and no amount field is hidden in it. A hook that emits a malformed, or
  value-bearing, or no-repeat CronSet is refuted with a counterexample. It does not trust the two type
  bytes.
- **Layer 2, confirmed on testnet, not provable from bytecode.** Whether the ledger accepts the emit
  and REPLACES the schedule rather than stacking a second one is a fact about how xahaud applies a
  CronSet, which no proof over the program can reach. Confirmed on testnet account
  `rwzdLQH4DwksDXTNZDu5M3mjFgkC4JcStp`: the emitted CronSet applied with tesSUCCESS, a Cron object
  appeared (repeat count 9 after the first fire, 60 second delay), and a separate probe confirmed the
  replace-not-stack behavior.

So schedule-liveness of the program is proven, and the on-ledger apply is confirmed on testnet. Neither
is hidden behind the other, and neither is called "proven" when it is not.

## Honest edges (a proof does not remove these)

- **Liveness** — the proofs bound what the hook *can* do (safety); they do not by themselves show the
  release *eventually* fires. Safety proofs are blind to liveness.
- **SetHook admissibility** — a hook can be proven and lint-clean and still be refused by the ledger
  at install (e.g. a guard written in a loop condition installs as `temMALFORMED`). Proven ≠ live ≠
  installable. This is stated in the source where it bit.

## Parameters and state

- `deadman_seeded.c` — HookParameters: `PAY` (20B beneficiary), `AMT` (8B BE drops per release),
  `CAP` (8B BE total), `TMO` (8B BE inactivity timeout, in ledger seconds).
- `deadman_seeded_multi.c` — `PA1`/`PA2` (two 20B beneficiaries), `AM1`/`AM2` (8B BE drops each),
  `CAP`, `TMO`. One firing pays each beneficiary its amount; `CAP` bounds the lifetime total.
- `deadman_seeded_rearm.c` — same parameters as `deadman_seeded.c` (`PAY`/`AMT`/`CAP`/`TMO`); it adds
  the self-rescheduling CronSet emit described above.
- HookState (both): `{0x01}` cumulative paid, `{0x02}` last owner-activity time.
- Fails closed on any decode / state / overflow / time anomaly. It is a spending authority: when in
  doubt, no release.

## Build / test / reproduce

The hooks are public: you can build each one and run its full lifecycle on Xahau testnet yourself. A
wasm32-capable clang is required (Apple clang does not have the target; use brew LLVM).

```
# build (public toolchain)
CC=/opt/homebrew/opt/llvm/bin/clang xahc build deadman_seeded.c -o deadman_seeded.wasm
# then deploy + exercise on testnet (SetHook, arm, Cron fire past the timeout) — see the smoke log
```

The formal proof is our own attestation. The prover (`xahc-prover`, symbolic execution + SMT) is our
tool and is **not** included in this bundle — so the "What is proven" list is a claim we stand behind,
reproducible in principle by any sound symbolic-execution + SMT setup over this exact bytecode, not a
command you run from these files. What you can independently check here is the code and its testnet
behavior. The whole reason `deadman_early_bug.c` ships is so the refuted case is inspectable too: the
safety bound holds on it, yet "release only after real inactivity" does not — which is the point.

Full lifecycle exercised on Xahau testnet in one run (fresh faucet accounts, NetworkID 21338),
HookHash `6AD641663C63EF00405BA35C2F25BCFECCCE25298AA4DB712A2CB9CD6A30FB53`:

- deploy (SetHook): `D77417830209D7145FBD448DAB16D599D076AEF4F999562F15C006433E30F0A5`
- arm on owner activity (Payment): `F124D2A333B07DD181C7214BBA6E4ED05737E5A043B3B37F5D517F8E0B444036`
- schedule the Cron series (CronSet): `821DDD4E58B3992F23D95002C56F194978F008957A5143E3F7C1A10C781BACC8`
- two fires inside the timeout: accepted, released nothing
- the fire past the timeout (ledger 11456218): released exactly one 1,000,000-drop allotment to the
  beneficiary; beneficiary balance rose by exactly that amount
- the next two fires: refused, allocation exhausted (no repeat payout)

owner `r4P1Xr4UYwmDCk4fNirh9ZrU9MJFdBj8jZ` · beneficiary `rNtRzptfYjbHmKwVD476cuKD8A7aaTVzr2`.
Explorer: `https://explorer.xahau-test.net/tx/<hash>`. Three distinct outcomes (hold / release / refuse)
in a single run is the point: a hook that only ever paid out would not be distinguishable from this one.

## Scope

Testnet, reference example. The moat is the prover, not this hook — this file is shared so the failure
mode is out in the open. Reuse it, but prove your variant before you trust it.

## License

Apache-2.0 (see `LICENSE` and `NOTICE`). The code is free to build, run, modify, and redistribute,
including commercially. "Kairo Vault", "Kairo Vault Technologies", and "KVT" are trademarks and are not
licensed by that grant; the prover (`xahc-prover`) is a separate, proprietary tool and is not included.

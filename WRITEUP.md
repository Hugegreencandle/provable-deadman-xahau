# A dead-man switch you can prove won't misfire

A dead-man switch is simple to describe and dangerous to get wrong. You want funds to pass to
someone after you go silent for long enough, with no custodian holding your keys and no multisig to
coordinate. On Xahau you can build this as a Hook on your own account. It watches for your activity,
and if you stop touching the account for longer than a timeout, it releases a capped amount to a
nominated beneficiary.

The hard part is not the happy path. It is the one thing the switch must never do, which is release
while you are still alive. Hand your family's money out too soon and there is no undo. It is also
easy to write that mistake in a way that reads correct.

I built one, ran the full lifecycle on Xahau testnet, and I am publishing the code. The interesting
part is the bug the obvious version has, and the fact that only a proof caught it.

## What it does

Against the exact bytecode, a symbolic-execution and SMT prover checks each property for every
possible input, or returns a concrete counterexample. The shipping single-beneficiary hook
(`deadman_seeded.c`) holds all of these:

- A release implies `now >= last_seen + TMO`. It never pays before the timeout.
- Only your own transaction resets the timer. A scammer depositing dust can never keep the switch
  from firing, and cannot push the release out either.
- The lifetime total paid never exceeds the configured `CAP`.
- Every release goes to the nominated beneficiary. The hook cannot be driven to pay anyone else.
- At most one release per firing, release only on the account's own Cron fire, persisted state never
  moves backwards, and the hook always terminates cleanly.

The two-beneficiary version (`deadman_seeded_multi.c`) carries the same set, with conservation as an
inductive step: prior `paid <= CAP` implies `paid + (AM1 + AM2) <= CAP`, and the persisted total only
moves forward, so the distribution never exceeds `CAP` and each share is locked to its own
beneficiary.

## The bug the obvious version has

The naive version reads the stored "last activity" time and, if none exists, treats it as zero. Zero
means inactive since the start of the epoch. So on a freshly installed account that has simply never
transacted, the first time the switch fires it decides the owner has been silent for about 26 years
and releases the funds, against an owner who is alive and well.

The formal safety bound (`release only when now >= last_seen + TMO`) stays true the whole time. The
property everyone believed it had, release only after real inactivity, was not true. The prover
refuted the naive hook and handed back the exact input that triggers it. The fix is one line: require
the activity record to be present before releasing. No recorded activity does not mean the owner is
silent. It means we have never looked.

There is a second, subtler trap. Put that presence check in the wrong place and you lock the owner
out of arming their own switch, a liveness failure no safety proof can see by construction. The rule
that falls out of it: fail closed on the spending path, fail open on the liveness path.

I shipped the refuted version too, as `deadman_early_bug.c`, so the failure is inspectable. Build it,
run the proof, watch it come back as a counterexample. That is the whole argument for proving money
Hooks instead of reading them. The bug is not exotic. It is the shape of mistake a careful engineer
makes, and only a proof over all inputs reliably catches it.

## Honest scope

- The proofs cover what the Hook's bytecode does for all inputs. They do not cover a specific
  deployment. Your HookOn flags, your account reserve, and the Cron install are your responsibility.
- The prover (`xahc-prover`, symbolic execution plus SMT) is my own tool and is not part of the
  public bundle. So the proven list is a claim I stand behind, reproducible in principle by any sound
  symbolic-execution and SMT setup over this exact bytecode, not a command you run from these files.
  What you can check directly is the code and its testnet behavior.
- These are testnet reference Hooks, not audited for your specific configuration, with no warranty.

## Testnet evidence

Full lifecycle on Xahau testnet in one run, fresh faucet accounts, NetworkID 21338, HookHash
`6AD641663C63EF00405BA35C2F25BCFECCCE25298AA4DB712A2CB9CD6A30FB53`:

- deploy (SetHook): `D77417830209D7145FBD448DAB16D599D076AEF4F999562F15C006433E30F0A5`
- arm on owner activity (Payment): `F124D2A333B07DD181C7214BBA6E4ED05737E5A043B3B37F5D517F8E0B444036`
- schedule the Cron series (CronSet): `821DDD4E58B3992F23D95002C56F194978F008957A5143E3F7C1A10C781BACC8`
- two fires inside the timeout: accepted, released nothing
- the fire past the timeout (ledger 11456218): released exactly one 1,000,000-drop allotment; the
  beneficiary balance rose by exactly that amount
- the next two fires: refused, allocation exhausted, no repeat payout

Three distinct outcomes in one run (hold, release, refuse) is the point. A hook that only ever paid
out would not be distinguishable from a correct one.

## The code

Public, Apache-2.0: https://github.com/Hugegreencandle/provable-deadman-xahau

Single-beneficiary, two-beneficiary, the refuted early-release version, and a self-re-arming variant,
with the proven-property list, the honest edges, and the full testnet log. Reuse it, but prove your
variant before you trust it.

## Why this matters

A wallet shows you a balance. It does not show you whether the Hook holding your inheritance can
misfire. A subtly wrong money Hook hands out funds too soon, and only a proof over every input catches
that before it is deployed. That is the layer I build: independent verification for Xahau Hooks. The
dead-man switch is the worked example. The code is public. Test it and try to break it.

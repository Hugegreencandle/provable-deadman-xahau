# A switch that re-arms itself, and where the proof stops

The first writeup shipped a dead-man switch and the bug a proof caught. It left one thing out on
purpose. The switch fires on a Cron, and a Cron series is finite. Schedule a hundred checks and after
the hundredth the switch goes quiet. A real inheritance switch has to keep watching for years, with
nobody logging in to renew it. So it has to re-arm itself.

The re-arming version does exactly that. Every time the Cron fires and the owner is still active, the
hook emits a new CronSet that schedules the next check. The schedule perpetuates on its own. This is
the useful version. It is also the version where a proof runs into the edge of what a proof can do,
and I think that edge is the interesting part.

## What the proof reaches

The re-arm is an emitted transaction. The naive way to check it is to read the two bytes that say
"this is a CronSet" and call it done. That is a byte tag, and a byte tag proves nothing. A hook can
write those two bytes onto a blob that is not a valid CronSet at all, or a CronSet that carries no
repeat and so schedules nothing.

So the prover does not trust the tag. It walks the emitted object field by field and proves it is a
structurally valid re-arming CronSet: the transaction type is CronSet, a real RepeatCount field is
present and at least one, and there is no amount field hiding in it. Only then does the re-arm count.
A hook that emits a malformed CronSet, or one with the type byte set on a blob that carries value, is
refuted with a concrete counterexample. This holds for every input.

## Where the proof stops

Here is the honest edge. The prover proves the hook EMITS a valid re-arming CronSet. It cannot prove
the ledger ACCEPTS that emit and REPLACES the old schedule rather than stacking a second one beside
it. That is not a fact about the hook's bytecode. It is a fact about how xahaud applies a CronSet, and
no amount of reasoning over the program can reach it.

That half is confirmed a different way, on testnet. I hand-encoded the CronSet emit, deployed it, and
watched it fire. The emitted CronSet applied with tesSUCCESS, a Cron ledger object appeared on the
account with a repeat count of 9 remaining after the first fire and a 60 second delay, and a separate
probe confirmed that a second re-arm replaces the schedule rather than stacking a new one beside it.
The run is on testnet account rwzdLQH4DwksDXTNZDu5M3mjFgkC4JcStp (deploy 6ADC14CD, trigger 42016E38),
searchable on the explorer.

So the self-re-arm rests on two different kinds of evidence. The structural half is proven for all
inputs. The ledger-apply half is confirmed on testnet. Stating which is which, out loud, is the whole
point. A proof earns trust by refusing to claim the thing it cannot see.

## The proof I got wrong first

The first version of this re-arm proof was itself wrong, and catching it is the reason I trust the
current one.

That version asked the wrong question. It treated a firing as "re-armed" whenever the hook made
progress, and it read progress as a bump to the paid counter. So a hook that bumped its counter but
emitted nothing, and therefore never rescheduled and let the whole series lapse, came back PROVEN. The
property I cared about (the schedule perpetuates) was not the property I had encoded (a counter went
up). Those are different, and the gap was a false proof of the exact thing the feature exists to do.

I found it by red-teaming my own driver with an adversarial twin: a hook that looks like it re-arms
but emits nothing on a holding fire. The fix has two parts. A firing only counts as a release when the
persisted total strictly increases, and a holding fire has to emit a real CronSet, checked
structurally as above, before it counts as re-armed. The twin that emits nothing now fails closed. The
genuine re-arming hook still passes.

The lesson generalizes. A proof is only as good as the property you hand it, and the twin you test it
against has to be adversarial. A hook that simply does nothing is too weak to expose a proof that
rewards the wrong signal. The twin has to try to look correct while being wrong.

## The code

The self-re-arming hook is in the same repo as the first writeup, Apache-2.0, with the two-layer scope
written into the README: https://github.com/Hugegreencandle/provable-deadman-xahau

## Why this matters

Anyone can write a hook that emits something shaped like a CronSet and call the switch self-renewing.
The question is whether it actually reschedules, for every input, and whether the ledger keeps one
live schedule instead of a growing pile. The first half is provable and I proved it. The second half
is a ledger fact and I confirmed it on testnet. The work is not hiding either one behind the word
"proven." Independent verification for Xahau Hooks means naming the boundary and standing on both
sides of it honestly.

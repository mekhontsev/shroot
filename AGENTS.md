# Shroot Repository Instructions

Shroot is an independently versioned native ARM64 Linux runtime and environment
manager. Production build and execution must not require Java, ART, app_process,
an Android APK, or a MagicDesk checkout. Android and ordinary ARM64 Linux use one
engine, with capabilities checked at the owning host boundary. Do not infer
authority from an application's package name or silently elevate privileges.

Preserve existing unrelated work. Git commits and publication require the user's
authorization. Keep NFC refactoring separate from behavior changes;
commit coherent verified blocks, not individual editing steps.

## Ownership

Read architecture.md and the relevant focused contracts before changing a mechanism.
Runtime resource owners define semantics once across native, Base and lazy-SVC
paths. Frontends adapt arguments, descriptors and results; they must not duplicate
filesystem, policy, lifecycle or namespace implementations. Ordinary native IO
must remain direct. Guest policy checks and signals remain meaningful.

For performance work, first identify which guest operations cause stops,
wakes or RPCs and which processes issue them. Before optimizing the exchange,
ask whether the guest can complete the operation natively or locally using
state it already owns. Delegate only what needs an authoritative owner. Prove
eligibility by resource identity, lifetime and guest semantics, not by program
or path name. When evidence is missing or changes concurrently, keep the
authoritative path. Verify both paths and measure end-to-end CPU and latency,
including helpers; fewer supervisor events alone do not establish a win.

Implement guest behavior using mechanisms available on Android under app UID,
shell UID 2000, or both. Prefer one implementation across both identities and
ordinary ARM64 Linux. Add a distinct execution path only for a real capability
difference between supported Android identities; select it by capability, not
by UID or OS name. Do not add a Linux-only guest execution path merely because
the host permits it.

The public C management API starts the native runtime out of process. Do not
load its syscall adapter or process-global supervision into an embedding host.
Runtime thread topology and filesystem-worker readiness belong to the existing
supervisor owner, not public thread-start functions. Keep library callers' signal,
descriptor, environment and identity ownership explicit.

Keep host integration optional and capability-scoped. Runtime tasks and storage
retain their launch identity. Android APK packaging, authorization and UI belong
to the integrating application. Logical guest separation is not a security
boundary for hostile code; independent Android UIDs supply an outer sandbox.

## Compatibility

Linux 5.15 is the minimum supported kernel. Record newer capability dependencies,
fallbacks or explicit errors and coverage in kernel-compatibility.md. Version
numbers and headers alone do not prove permission or required semantics.

Storage family 17 and later supported revisions preserve installed environments,
identities and source dependencies. Runtime version, storage family, metadata
revision and image import identity are independent. Never bump persisted formats
for runtime tuning. Metadata upgrades belong to exclusive storage admission,
not syscall paths. Unknown newer revisions fail without deletion.

## Verification

Build hosts are Linux and Android/Termux. Windows users use Linux tools in WSL2;
do not add native Windows CI jobs or build prerequisites.

When fixing a defect, audit analogous entry points, executors, lifecycle and
failure paths across the owning mechanism. Add focused regression tests using
the shared fixtures. Report unverified paths; a single successful reproduction
is not proof of general correctness.

For lost assertions in unit tests or distribution workloads, including new
failures within an already failing test, compare good and bad runtimes with
the same guest data and host. Test persistent-state changes independently.
Identify the first bad change or report the verified bounds. Explain why the
available coverage did not catch it. For shared SVC changes, exercise the
affected semantics through both Base and lazy SVC; for a lazy-specific assertion
verify that the call actually used lazy entry. Recheck the original workload.

For defects exposed by nesting, reduce the failure to a single-runtime
regression where possible. Verify the same assertions before and after the fix
at one level, then qualify the fix at the depth that exposed it.

Keep host component, runtime and real-application tests distinct. Reuse assertions
across transport adapters and identities. Retain native controls and sandbox
policy. Do not weaken assertions, enlarge application timeouts or silently skip
unsupported operations to make a test pass. Record runtime identity, host kernel,
page size and capabilities. Test in disposable stores and clean their owned
processes and files. Never reboot a device without immediate user confirmation.

Nesting depth belongs to the test runner. Do not pass it to a fixture to
select code paths, expected results, iteration counts or protocol timeouts.
Distinguish a timeout being tested from the watchdog observing the test.

Maintain documentation about current behavior, limitations, ownership and usage;
keep experiment chronology in artifacts and Git. Release notes own versioned
changes. Keep host-independent probes and engine contracts here. The integrating
project owns its installer, graphical recipes and corresponding test payloads;
link there for application-specific setup instead of duplicating its manual.
All substantive source edits use apply_patch; mechanical relocation or
bulk path rewrites may use appropriate tooling.

# UFW Menu Cache Design

## Goal

Make switching between UFW submenus responsive by avoiding repeated synchronous `ufw status` commands while preserving accurate state after every managed change.

## Scope

The optimization applies only while the user remains inside the UFW module. It covers the main UFW screen and the inbound, outbound, forwarding, and status submenus.

It does not add disk caches, background jobs, timers, cross-process state, command-line options, or changes to SSH and Fail2Ban menus.

## Snapshot

The UFW module keeps one in-memory snapshot containing:

- `ufw status numbered`
- `ufw status verbose`
- `ufw show added`
- the active or inactive state derived from the captured status

The snapshot is populated on the first screen that needs it. All UFW screens read the same snapshot instead of invoking UFW again during navigation.

Entering the UFW module invalidates any prior snapshot so changes made outside the module become visible on re-entry.

## Invalidation

Any attempted UFW mutation invalidates the snapshot before the next screen is rendered. This includes:

- adding or deleting inbound rules
- adding or deleting outbound rules
- adding or deleting forwarding rules
- initializing, enabling, disabling, or reloading UFW
- changing the UFW logging level

Invalidation occurs even when an action reports failure because a command can partially alter state before returning a nonzero status.

SSH migration helpers do not update the snapshot directly. Their changes become visible because entering the UFW module always invalidates and refreshes it.

## Rendering

Existing screen content remains unchanged. Status helpers receive or read cached text instead of executing `ufw status`, and the main UFW screen derives its enabled label from the cached snapshot.

The first UFW screen may take approximately the same time as before because it builds the snapshot. Subsequent submenu switches perform only Bash string filtering and rendering until a mutation invalidates the snapshot.

## Error Handling

A snapshot is valid only when all three capture commands complete successfully. A failed refresh prints a concise error and leaves the cache invalid so the next screen can retry.

The optimization must not reuse partial output, hide command failures, modify UFW state, or suppress existing action errors.

## Testing

Extend `tests/linux_security_self_test.sh` with a fake `ufw` function that records invocations and returns deterministic status text.

Verify that:

1. Multiple screen reads populate the snapshot once
2. Invalidation causes exactly one new population on the next read
3. Active state and displayed rules come from the same snapshot
4. A failed refresh does not mark the snapshot valid
5. Existing UFW SSH lifecycle and system security checks still pass

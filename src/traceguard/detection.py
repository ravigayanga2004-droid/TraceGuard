"""Compare observations, including conservative rename matching."""

from collections import defaultdict

from traceguard.models import Event, FileRecord


def differences(before: dict[str, FileRecord], after: dict[str, FileRecord]) -> list[Event]:
    removed = set(before) - set(after)
    added = set(after) - set(before)
    events: list[Event] = []
    # Match unique stable identities first, then unique hashes for cross-device moves.
    for identity in (True, False):
        old: dict[object, list[str]] = defaultdict(list)
        new: dict[object, list[str]] = defaultdict(list)
        for paths, records, groups in ((removed, before, old), (added, after, new)):
            for path in paths:
                item = records[path]
                key = (item.device, item.inode) if identity else (item.sha256, item.size)
                if not identity or item.inode:
                    groups[key].append(path)
        for match_key in old.keys() & new.keys():
            if len(old[match_key]) == len(new[match_key]) == 1:
                source, destination = old[match_key][0], new[match_key][0]
                events.append(
                    Event(
                        kind="renamed",
                        path=destination,
                        old_path=source,
                        before=before[source],
                        after=after[destination],
                    )
                )
                removed.remove(source)
                added.remove(destination)
    for path in sorted(removed):
        events.append(Event(kind="deleted", path=path, before=before[path]))
    for path in sorted(added):
        events.append(Event(kind="created", path=path, after=after[path]))
    for path in sorted(before.keys() & after.keys()):
        left, right = before[path], after[path]
        if left.sha256 != right.sha256:
            events.append(Event(kind="modified", path=path, before=left, after=right))
        elif (left.mode, left.uid, left.gid, left.mtime_ns) != (
            right.mode,
            right.uid,
            right.gid,
            right.mtime_ns,
        ):
            events.append(Event(kind="metadata", path=path, before=left, after=right))
    return sorted(events, key=lambda event: (event.path, event.kind))

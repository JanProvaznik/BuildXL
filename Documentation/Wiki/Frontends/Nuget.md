# The NuGet resolver and its repository list

The NuGet resolver downloads packages declared in `config.dsc` and turns each one into a generated
DScript spec. Two aspects of how it treats the *set* of configured repositories surprise people
often enough to be worth writing down, because neither is visible from the configuration and both
present as unrelated failures.

## Every configured repository must be reachable before any package downloads

`NugetPackageInspector.TryInitializeAsync` resolves the service index of every configured repository
up front, and returns `NoBaseAddressForRepository` on the first one it cannot reach. Initialization
is all-or-nothing, so a single unreachable feed blocks downloading *every* package - including
packages that are available on a different, reachable feed.

That is a deliberate asymmetry rather than an oversight, and it is worth seeing the contrast. Once
initialization succeeds, the *lookup* of an individual package does fall back: `TryInspectAsync`
walks the base addresses in turn and returns the first that has the package. So a package missing
from one feed is fine; a feed that is unreachable is not.

**A fully cached build never hits this**, which is why it is not seen more often. Initialization is
deliberately deferred - `WorkspaceNugetModuleResolver` only calls `TryInitAsync` from inside the
download callback, with the comment *"We want to delay initialization until the first inspection
that is actually needed"* - so a build whose packages are all in the local NuGet cache never touches
the network. The failure needs two conditions at once: at least one package to download, **and** at
least one unreachable feed.

Those conditions coincide more often than they sound. A fresh clone, a CI agent with a cold cache,
or a newly added dependency all satisfy the first; a feed outage or restricted egress satisfies the
second. BuildXL's own public configuration lists two repositories, so an external contributor
building from a clean state needs both of them reachable.

The error names the repository it failed on:

```
error DX11331: Nuget failed to download package 'Grpc.Tools': Failed to process nuget packages due
to NoBaseAddressForRepository. Unable to load the service index for source https://api.nuget.org/v3/index.json.
```

When this appears for a package that has nothing to do with the named feed, the feed is the problem,
not the package.

## The repository list is part of every package's cache key

`WorkspaceNugetModuleResolver.CreateRestoreFingerPrint` builds a package's restore fingerprint from
its id, its version, **and the full set of configured repositories**:

```
nuget://id=Grpc.Tools&version=2.71.0&repos=HTTPS://API.NUGET.ORG/V3/INDEX.JSON,HTTPS://PKGS.DEV.AZURE.COM/...&cred=
```

You can read it directly - it is the third line of `Out/frontend/Nuget/pkgs/<Package>.<Version>/hash.txt`.

The consequence is that **adding or removing any repository invalidates the cached download of every
package**, not just packages that came from the feed that changed. On a machine that can reach the
feeds this costs a re-download. On a machine that cannot, it is fatal: an unrelated package fails
immediately with

```
error DX11331: Nuget failed to download package 'NLog': Package nuget://NLog/4.7.7 could not be restored.
```

which names a package that has nothing to do with the edit.

Repository *order* does not matter. `UppercaseSortAndJoinStrings` upper-cases and sorts the list, so
reordering entries is free. Only the set membership matters.

### Practical consequences

- **Do not edit the repository list to work around an unreachable feed.** It converts one failing
  feed into a completely cold NuGet cache, which is strictly worse. Restore network access to the
  feed, or work from the packages already cached.
- **Adding a local feed for local iteration is safe, but is a one-time cost.** The first build after
  adding it re-downloads everything, because every fingerprint changed. Add it once and leave it.
- **The fingerprint is a good first thing to read when a package "mysteriously" re-downloads.**
  Comparing `hash.txt` against the current `config.dsc` repository list usually explains it in a
  single diff.

### Why it is keyed this way

The fingerprint has to change when the repository list changes, because the same package id and
version can resolve to different content on different feeds - that is precisely what an upstreaming
or mirroring feed does. Keying only on id and version would let a package fetched from one feed be
reused silently after the configuration was pointed at another, which is a correctness problem
rather than a performance one. The cost is the coarse invalidation described above.

# MOQT Scope Design: Multi-Dimensional Matching

## Overview

A MOQT CAT token carries one or more **scopes**. Each scope defines what
actions a client may perform and on which resources. Authorization succeeds
when **any** scope grants the request (OR across scopes), while **within** a
scope every constraint must be satisfied (AND across dimensions and within
each dimension).

## Scope Structure

```
Token
 └── Scopes[]                         ← OR (any scope authorizes)
      └── Scope
           ├── actions: [PUBLISH, SUBSCRIBE, ...]
           ├── namespace_match: CompoundMatch    ← AND across dimensions
           └── track_match:     CompoundMatch    ← AND across dimensions
```

Each `CompoundMatch` holds one or more `BinaryMatch` conditions that are
AND-ed together within that dimension:

```
CompoundMatch
 └── conditions[]                     ← AND (all must match)
      ├── BinaryMatch { type: PREFIX, pattern: "/live/" }
      └── BinaryMatch { type: SUFFIX, pattern: ".mp4"  }
```

## Authorization Logic

```
                         ┌─── actions: [PUBLISH, SUBSCRIBE]
                         │
Scope ── AND across ─────┼─── namespace dimension: [prefix("streaming."), suffix(".example")]
         dimensions      │                           └── AND within dimension
                         │
                         └─── track dimension: [prefix("/video/"), contains("hd")]
                                                └── AND within dimension
```

A request `(action, namespace, track)` is authorized if:

```
ANY scope where:
    action ∈ scope.actions
    AND scope.namespace_match.matches(namespace)   ← all conditions pass
    AND scope.track_match.matches(track)           ← all conditions pass
```

## Match Types

Each `BinaryMatch` condition uses one of:

| Type     | Semantics                          | Example                     |
|----------|------------------------------------|-----------------------------|
| EXACT    | `data == pattern`                  | `exact("live.example.com")` |
| PREFIX   | `data.starts_with(pattern)`        | `prefix("/live/")`          |
| SUFFIX   | `data.ends_with(pattern)`          | `suffix(".mp4")`            |
| CONTAINS | `data.contains(pattern)`           | `contains("hd")`           |
| ANY      | always matches (empty conditions)  | `MoqtCompoundMatch::any()` |

## Examples

### Single condition per dimension (simple case)

```cpp
// Publisher can announce/publish on exact namespace, any track starting with /live
std::array actions = {moqt_actions::PUBLISH, moqt_actions::ANNOUNCE};
claims.addScope(actions,
    MoqtBinaryMatch::exact("streaming.example"),
    MoqtBinaryMatch::prefix("/live"));
```

### Multiple AND-ed conditions on namespace

```cpp
// Only namespaces starting with "streaming." AND ending with ".example"
std::array actions = {moqt_actions::PUBLISH};
claims.addScope(actions,
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("streaming."),
        MoqtBinaryMatch::suffix(".example"),
    }),
    MoqtCompoundMatch::single(MoqtBinaryMatch::prefix("/live")));

// Matches: "streaming.media.example", "streaming.cdn.example"
// Rejects: "streaming.media.other", "other.media.example"
```

### Multiple AND-ed conditions on track

```cpp
// Only tracks that are under /video/ AND are .mp4 files
std::array actions = {moqt_actions::SUBSCRIBE, moqt_actions::FETCH};
claims.addScope(actions,
    MoqtCompoundMatch::single(MoqtBinaryMatch::exact("cdn.example")),
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("/video/"),
        MoqtBinaryMatch::suffix(".mp4"),
    }));

// Matches: "cdn.example" + "/video/clip.mp4"
// Rejects: "cdn.example" + "/video/clip.webm"  (suffix fails)
// Rejects: "cdn.example" + "/audio/clip.mp4"   (prefix fails)
```

### Compound conditions on both dimensions

```cpp
// HD live video streams from trusted providers
std::array actions = {moqt_actions::SUBSCRIBE};
claims.addScope(actions,
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("live."),
        MoqtBinaryMatch::suffix(".tv"),
    }),
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("/hd/"),
        MoqtBinaryMatch::contains("stream"),
    }));

// Matches: "live.sports.tv" + "/hd/stream-001"
// Rejects: "live.sports.com" + "/hd/stream-001"  (ns suffix fails)
// Rejects: "live.sports.tv" + "/sd/stream-001"   (track prefix fails)
// Rejects: "live.sports.tv" + "/hd/clip-001"     (track contains fails)
```

### Multiple scopes (OR logic)

```cpp
auto claims = MoqtClaims::create();

// Scope 1: publish to live streams
std::array pub = {moqt_actions::PUBLISH};
claims.addScope(pub,
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("live."),
        MoqtBinaryMatch::suffix(".tv"),
    }),
    MoqtCompoundMatch::single(MoqtBinaryMatch::prefix("/hd")));

// Scope 2: subscribe to VOD catalog
std::array sub = {moqt_actions::SUBSCRIBE};
claims.addScope(sub,
    MoqtCompoundMatch::single(MoqtBinaryMatch::exact("vod.example")),
    MoqtCompoundMatch::all({
        MoqtBinaryMatch::prefix("/catalog/"),
        MoqtBinaryMatch::contains("2024"),
    }));

// PUBLISH authorized via scope 1:
claims.isAuthorized(PUBLISH, "live.sports.tv", "/hd/stream1");  // true

// SUBSCRIBE authorized via scope 2:
claims.isAuthorized(SUBSCRIBE, "vod.example", "/catalog/2024-best");  // true

// Neither scope matches:
claims.isAuthorized(PUBLISH, "vod.example", "/catalog/2024-best");  // false
```

## CBOR Wire Format

Each scope is encoded as:

```
scope = [
    [action, action, ...],            ; actions array
    [ns_match, ns_match, ...],        ; namespace: array of match conditions (AND)
    track_match | [tr, tr, ...]       ; track: single match OR array of conditions (AND)
]
```

Each `match` condition is:

```
match = bstr                          ; EXACT match (bare bytestring)
      | [uint, bstr]                  ; [match_type, pattern]
                                      ;   1 = PREFIX, 2 = SUFFIX, 3 = CONTAINS
```

The namespace field is always an array (even for single conditions), providing
forward-compatible compound support. The track field uses a bare match for
single conditions (backward compatible) and an array for multiple conditions.

## API Reference

### MoqtCompoundMatch

| Method | Description |
|--------|-------------|
| `MoqtCompoundMatch::any()` | Matches everything (no conditions) |
| `MoqtCompoundMatch::single(match)` | Single condition (same as before) |
| `MoqtCompoundMatch::all({m1, m2, ...})` | Multiple AND-ed conditions |
| `match.matches(str)` | Test if all conditions match |
| `match.is_empty()` | True if no conditions (matches all) |
| `match.size()` | Number of conditions |
| `match.conditions()` | Access underlying conditions |

### MoqtBinaryMatch

| Method | Description |
|--------|-------------|
| `MoqtBinaryMatch::exact(pattern)` | Exact equality |
| `MoqtBinaryMatch::prefix(pattern)` | Starts-with |
| `MoqtBinaryMatch::suffix(pattern)` | Ends-with |
| `MoqtBinaryMatch::contains(pattern)` | Substring |
| `MoqtBinaryMatch::any()` | Match all (empty pattern) |

### Adding scopes to claims

```cpp
// Single match per dimension (convenience, backward compatible)
claims.addScope(actions, MoqtBinaryMatch::prefix("ns"), MoqtBinaryMatch::suffix("tr"));

// Compound match per dimension
claims.addScope(actions,
    MoqtCompoundMatch::all({...}),
    MoqtCompoundMatch::single(...));
```

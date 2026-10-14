# Triage event timestamps

The service uses `analysis.submitted` as the analysis epoch. It parses
`analysis.submitted` and `analysis.reported` as timezone-aware RFC3339 timestamps,
normalizes both to UTC, and retains fractional seconds. Missing timezones and
reversed analysis windows fail explicitly. The dynamic helper accepts UTC strings
in `YYYY-MM-DD HH:MM:SS.ffffff` format; AL's Date ODM exports them with a `Z` suffix.
These strings represent UTC regardless of the service host's local timezone.

| Upstream field | Unit / epoch | Service mapping |
| --- | --- | --- |
| `analysis.submitted`, `analysis.reported` | Absolute RFC3339 UTC | Sandbox start/end and event epoch |
| `processes[].started` | Integer milliseconds from analysis start | Process start and object observation time |
| `processes[].terminated` | Integer milliseconds from analysis start | Process end, when observed |
| `network.flows[].first_seen` | Integer milliseconds from analysis start | Connection object observation time, shared by its DNS/HTTP transaction objects |
| `network.flows[].last_seen` | Integer milliseconds from analysis start | Not mapped: the connection ODM has no end-time field |
| `network.requests[].at`, `signatures[].indicators[].at` | Integer millisecond offsets in observed reports | Not mapped to absolute time; request evidence retains raw upstream values |
| `dumped[].at` | Integer milliseconds from analysis start | Not mapped to absolute time; used only as raw artifact metadata |
| `analysis.max_time_kernel`, `analysis.max_time_network` | Milliseconds in observed reports | Not mapped or used as a replacement epoch/window |

## Contract evidence

[Triage's API conventions](https://tria.ge/docs/cloud-api/conventions/#time)
document absolute UTC RFC3339 timestamps. Its
[dynamic-report schema](https://tria.ge/docs/cloud-api/dynamic-report/) defines
integer process offsets (`uint32`), flow offsets (`int64`), and event `at` offsets
(`uint32`), but does **not** describe their units. The vendor's
[dropped-file guide](https://hatching.io/blog/dropped-files/) explicitly documents
`dumped[].at` as milliseconds relative to analysis start.

Process and network units are corroborated by real behavioral reports, rather
than the outdated local reference that described float seconds. For example, a
six-second `choice /t 6` process has `started=96000`, `terminated=102031`: a
6031 ms lifetime. The same report has an analysis window of 180 seconds,
`max_time_kernel=149281`, and process, flow, request, indicator and dump offsets
on the same millisecond scale. This supports millisecond interpretation; it is
empirical evidence, not an additional unit guarantee in the published schema.
No magnitude-based seconds/milliseconds detection is performed.

## Missing and malformed data

- Zero process starts and zero flow observations mean the analysis epoch. An
  absent process start cannot satisfy the Process ODM and omits that process with
  a diagnostic. An absent flow observation remains `None`.
- `terminated` is an optional Go field with `omitempty`; absent/null/zero means
  no observed termination. No year-9999 or analysis-end event is exported.
- Boolean, non-integer, negative and out-of-window mapped offsets are rejected
  with field-specific diagnostics. The window is the inclusive interval from
  submitted to reported. Invalid starts omit the process; invalid termination or
  flow times remain unknown while other evidence is retained. A termination
  before its process start is also diagnosed and left unknown.
- Offsets are never clamped and never retried as another unit or epoch.
- The dynamic helper needs its open-ended lifetime sentinel during PID/parent
  correlation. It is cleared after all mapping completes, before UI or ontology
  serialization, including nested network process references. These objects are
  finalized for rendering/export; no further lifetime correlation runs on them.

Regression tests cover millisecond ordering, analysis offsets/timezones,
subsecond precision, zero/missing/malformed values, window boundaries, and native
helper event-tree versus ODM exports (including nested process lifetimes).

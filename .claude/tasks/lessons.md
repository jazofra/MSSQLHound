# Lessons

- For Windows AD fallback paths, avoid `exec.Command("powershell", ...)` when in-process Go/COM/LDAP APIs can do the work. Fork/exec can be blocked by policy even when native ADSI works.
- With go-ole ADO collections, retrieve `Item` via property access first (`GetProperty(collection, "Item", name)`), not method invocation; otherwise provider properties like `Page Size` can fail with `Member not found`.
- Long-running AD enumeration must emit progress at info level and carry useful attributes like `objectSid` forward to avoid slow follow-up lookup loops.
- Long-running DNS/IP dedupe must emit info-level progress and avoid serial per-entry lookups; resolve unique hostnames concurrently with a bounded worker count.
- Before offering line-ending strategies, characterize each diffed file's actual endings on both sides (main vs HEAD), not just a sampled file. Repos can be mixed-ending: a "force all to LF" choice can add thousands of lines of churn if main itself has CRLF files. Tabulate categories (both-LF, both-CRLF, LF→CRLF drift, CRLF→LF drift, new files) and present the tradeoff with real counts before asking the user to choose.

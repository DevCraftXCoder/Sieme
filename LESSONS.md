# Engineering Lessons — SIEMen × SIC Integration

*Session: June 24, 2026*

Six concrete lessons from building and debugging this pipeline.

---

## Lesson 1 — Every HTTP client needs a User-Agent when hitting Cloudflare

Browsers identify themselves automatically — Chrome, Safari, Firefox all send a string like "Mozilla/5.0 ..." on every request. When you write your own HTTP client from scratch, it sends nothing unless you add that header manually.

Cloudflare's bot protection runs before your application code. It sees a request with no identity information and blocks it outright — not a 401 or 403 you can handle, just a hard deny at the edge. The error (1010) looks like a network or firewall problem, not a missing header.

**Rule:** Any custom HTTP client hitting a Cloudflare-protected endpoint needs a User-Agent header. It's one line. Without it, hours of debugging something that looks like a connection issue.

---

## Lesson 2 — Dry-run flags must guard every side-effecting call, not just the last one

A dry-run flag lets you simulate an operation without touching anything real. The bug is placing the guard too late — after some real work has already happened.

The broken pattern: a function opens a database record, then pushes data. The dry-run check sits before the push but after the open. The user is told nothing will be written, but a record was already created.

The correct pattern: the dry-run check is the very first thing in the function. If dry-run is true, compute what you *would* do and return that description — never call anything that creates, writes, or sends something real.

**Rule:** Work backwards through every function with a dry-run flag. If any real-world call happens before the guard, move the guard above it.

---

## Lesson 3 — Batch APIs need a clear rule about where shared fields live

When you batch multiple items in one request, some fields apply to all of them. You can put those fields at the top level of the request or repeat them on every item. Either works — but you must pick one and make sure your handler reads from that exact location.

What went wrong: the top-level field was accepted in the request but never read by the handler. Every item was missing the field it needed, so every item silently failed validation. The response was 200 OK. Stored count was zero. No errors were reported.

Silent zero-stored responses are among the hardest bugs to find. The request succeeds, the response looks clean, but nothing happened.

**Rule:** When designing a batch endpoint, write down where each field lives. Add a test that sends the shared field at the top level only and confirms the stored count is non-zero.

---

## Lesson 4 — Maintaining a public mirror requires an explicit sync rule

When the same codebase lives in two places — a private repo with real credentials and a public repo with placeholders — the copies drift unless there is a deliberate rule about what gets synced.

The dangerous case: automated or manual sync accidentally copies the private configuration (real database IDs, API keys) into the public repo. Once pushed, those credentials are exposed even if you delete them later, because git history is permanent.

The safe pattern: source code files sync freely. Configuration files with real credentials never leave the private copy. The public copy keeps clearly-labeled placeholders and those are never overwritten.

**Rule:** Document the sync boundary in both repos. Code = sync. Config with real values = never sync. Any sync script must explicitly exclude credential files by name, not by hoping someone notices.

---

## Lesson 5 — Git submodules are independent repos — commits inside them work differently

A git submodule is a full, separate git repository embedded inside another one. The parent only tracks a pointer — "this submodule is at commit abc123." It does not track the files inside the submodule directly.

The practical consequence: if you change a file inside a submodule and try to stage it from the parent, git refuses. You must go into the submodule directory, commit and push there first, then return to the parent to update the pointer.

This surprises people because from a file explorer, the submodule looks like any other folder. Git treats it as a completely separate repository.

**Rule:** Know which directories in your repo are submodules before editing them. Changes require two separate git operations: one inside the submodule, one in the parent to update the pointer.

---

## Lesson 6 — Test every handoff point in a pipeline, not just the final output

A pipeline with six stages and one broken link produces a wrong final result. Testing only the output tells you something is wrong but not where. You end up guessing and bisecting manually.

The better approach: test each seam independently. Call each stage and verify its output before that output becomes the input to the next stage. If stage 3 of 6 is broken, you find it in one check.

For this pipeline — scan data flowing through a bridge, into a data layer, through a report endpoint, into a mapper, and finally into an HTML template — each link was tested against live data. The result was a clear pass or fail per step, not a vague "the output is wrong."

**Rule:** For any pipeline longer than two stages, write down what goes in and what comes out at each stage. Test them in order. When one fails, stop — you already know where the break is.

---

*These lessons apply beyond this project. Save them where they'll be reviewed.*

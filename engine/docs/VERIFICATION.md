# Verification

The public verification for Pinga53 is the test suite:

```bash
cd engine && go test -race ./...
```

Earlier revisions of this file held the maintainer's run-by-run evidence
log (host captures, CI runs, syscall traces). That log names private
infrastructure, so it is kept out of the public repository. Where code
comments say a claim "is recorded in docs/VERIFICATION.md", the claim is
backed by a test in this repository or is explicitly marked as not
established.

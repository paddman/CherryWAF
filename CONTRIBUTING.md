# Contributing

1. Create a focused branch.
2. Run `make fmt vet test build`.
3. Add tests for behavior changes.
4. Keep security decisions deterministic and avoid external calls in the synchronous request path.
5. Document configuration changes and preserve backward compatibility within a configuration version.

Rule changes should include benign and malicious fixtures. Deploy new signatures in detect mode before enabling them in a production blocking policy.

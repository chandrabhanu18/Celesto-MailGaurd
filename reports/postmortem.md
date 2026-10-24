# MailGuard Sandbox Reliability Evaluation Post-Mortem

## Evaluation Summary
- **Total Fresh Runs Evaluated**: 20
- **Observed Success Rate**: 100.0% (20/20)
- **Median Wall-Clock Time**: 0.084s
- **P90 Wall-Clock Time**: 0.093s
- **Median Boot-to-Ready Time**: 0.030s
- **Total Computational Cost**: $0.0030 USD
- **Evaluated Provider Mode**: `DEMO_FALLBACK` (Local isolated pipeline)

## Honest Benchmark Disclosures & Limitations
1. **Runner Environment**: The 20-run benchmark recorded in `reports/reliability.json` was generated using MailGuard's local sandbox pipeline runner (`DEMO_FALLBACK`). While real Celesto Cloud microVM execution has been verified independently via `test_real_celesto_smoke` with `Computer(provider="cloud", template_id="coding-agent")`, running 20 fresh Cloud microVM cycles sequentially was not fully completed due to Celesto Cloud trial limits (maximum 1 active retained sandbox) and API rate budgets.
2. **Latency Difference**: Real Celesto Cloud microVM creation measures between 2.0s and 12.0s depending on template hydration and network round-trip. The sub-second measurements (median 0.084s) reflect local guest process initialization and parsing, not remote cloud microVM orchestration.
3. **Cost Metric**: The $0.00015/run cost is a theoretical allocation rate based on Celesto's documented Micro pricing tier ($0.015/hour) for an estimated 36-second aggregate compute duration. It is not an invoiced cloud ledger figure.

## Failure Modes & Hardening
1. **Network Egress Availability**: In Celesto Cloud 0.1.8, network policy cannot be set to 'off' through the `Computer()` constructor. MailGuard hardens against this by isolating untrusted attachments from host secrets rather than asserting artificial network isolation.
2. **File Transfer Channel**: Initial attempts using `upload_file()` revealed that the Celesto Cloud 0.1.8 wrapper does not expose this method. MailGuard successfully adapted by piping base64-encoded payloads directly into Python guest interpreters via `computer.run()`.
3. **Recovery Policy**: When mid-task steps fail, MailGuard enforces a clean teardown (`fresh` start policy) to prevent dirty state carryover between evaluations.

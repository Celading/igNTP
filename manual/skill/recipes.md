# igNTP: integration recipe

Use the complete executable example in [README](../../README.md). Point the consumer dependency at the directory containing the library package manifest, build it separately and execute the emitted binary.

Handle timeout, KoD, unsynchronized-server and transport errors. requestBest separates per-endpoint failures and may return no selected sample; do not treat an empty result as a synchronized clock.

The client reports time estimates and never changes the system clock. Every exchange has a monotonic budget. KoD backoff is keyed by host/resolved endpoint and bounded to 64 records. Invalid datagrams are discarded within the same budget; this is not unlimited waiting. Multi-server selection uses stratum, root delay and RTT, and reports failures separately.

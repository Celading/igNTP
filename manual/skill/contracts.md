# igNTP: integration contracts

Exact 48-byte packet encoding/decoding; NTP/Unix time conversion; offset and round-trip calculations; injectable clocks/transports; source endpoint and originate validation; bounded exchanges; per-endpoint Kiss-o'-Death backoff; sequential multi-server sampling and selection via requestBest.

Handle timeout, KoD, unsynchronized-server and transport errors. requestBest separates per-endpoint failures and may return no selected sample; do not treat an empty result as a synchronized clock.

The client reports time estimates and never changes the system clock. Every exchange has a monotonic budget. KoD backoff is keyed by host/resolved endpoint and bounded to 64 records. Invalid datagrams are discarded within the same budget; this is not unlimited waiting. Multi-server selection uses stratum, root delay and RTT, and reports failures separately.

No NTS/MAC authentication, clock discipline daemon, server/broadcast/symmetric role or automatic retransmission. Public-network availability is external and live tests are opt-in. A server receive timestamp of zero can make calculated delay unreliable; callers must apply an appropriate quality policy.

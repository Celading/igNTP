# igNTP: protocol and byte contracts

RFC 4330 is the recorded SNTP reference. Multi-server selection is an application policy, not an implementation of the complete NTP clock-discipline algorithms.

Exact 48-byte packet encoding/decoding; NTP/Unix time conversion; offset and round-trip calculations; injectable clocks/transports; source endpoint and originate validation; bounded exchanges; per-endpoint Kiss-o'-Death backoff; sequential multi-server sampling and selection via requestBest.

Keep fixed expected bytes or independently derived values alongside round-trip tests. Malformed-input cases must fail with the expected classification, not merely avoid a crash. A test-to-test agreement is not external interoperability certification.

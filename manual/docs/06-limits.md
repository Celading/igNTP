# igNTP: resource and trust boundaries

The client reports time estimates and never changes the system clock. Every exchange has a monotonic budget. KoD backoff is keyed by host/resolved endpoint and bounded to 64 records. Invalid datagrams are discarded within the same budget; this is not unlimited waiting. Multi-server selection uses stratum, root delay and RTT, and reports failures separately.

Tests must distinguish the accepted boundary from the immediately rejected neighbor. Limits are not an assertion of constant memory for all caller-owned inputs or unlimited concurrency.

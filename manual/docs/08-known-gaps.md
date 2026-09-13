# igNTP: limitations

No NTS/MAC authentication, clock discipline daemon, server/broadcast/symmetric role or automatic retransmission. Public-network availability is external and live tests are opt-in. A server receive timestamp of zero can make calculated delay unreliable; callers must apply an appropriate quality policy.

Both the library and its core test project use only the Cangjie standard library.

A source Preview is distinct from a publicly resolvable registry package. Use the documented local/extracted-package procedure until registry availability is independently confirmed.

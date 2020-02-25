# mldpoker
MLD Poker - A small utility that pokes sleepy devices for MLD Reports

``Usage: mldpoker IFNAME``

**IFNAME:** A bridge port interface, with the following properties:

* The bridge on top of it needs to have multicast_snooping enabled
* The bridge on top of it needs to have multicast_querier enabled
* The bridge on top of it needs to have a valid IPv6 link-local address

---

If a host behind ``IFNAME`` newly appeared or was unresponsive for at least 15 seconds and now reappeared then MLD Poker sends a general MLDv1 Query with an MLD Maximum Query Response Delay of 0 to it (request for an immediate, undelayed MLD Report). The MLD Query is sent to the target host directly via its unicast MAC address.

This tool was written to work around the following two issues:

* Roaming issues with Linux <= 4.9 [[0]](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a088d1d73a4bcfd7bc482f8d08375b9b665dc3e5)
* Android devices being unresponsive to MLD Queries in sleep mode [[1]](https://github.com/freifunk-gluon/gluon/issues/1832) [[2]](https://issuetracker.google.com/issues/149630944)

### Validation features

* DNSSEC validation in-tool
* -aka flag, for one or more "okay if it's this" hostnames
* pubkey anchors, not just cert anchors

### Other features

* output modes, including conforming to some monitoring tool expectations
* stdin mode?  Pipe commands on stdin, work in parallel with N-at-a-time resolution?

### Infrastructure

* testing framework
  + live servers to test against
  + what can reasonably be done without live servers?
    - since we take DNS_RESOLVER in environ, can always point it at a local
      fake resolver which returns stuff on localhost for all results

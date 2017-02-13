### Validation features

* DNSSEC validation in-tool
* -mx mode, to look up MX records and use as alternative verified hostname
* -aka flag, for one or more "okay if it's this" hostnames
* -srv mode, to look up SRV records; 587 & 465 benefit from this
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

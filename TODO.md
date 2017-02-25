### Validation features

* DNSSEC validation in-tool
* pubkey anchors, not just cert anchors
* Timeouts on connect

### Other features

* output modes, including conforming to some monitoring tool expectations
* stdin mode?  Pipe commands on stdin, work in parallel with N-at-a-time resolution?
* emit suggested anchors mode?
  + If no TLSA records, or if asked, _suggest_ anchors?
  + I can see how it might be useful, but it also encourages a bad habit,
    since the published anchors should be based on known-good data sources,
    not via connecting

### Infrastructure

* testing framework
  + live servers to test against
  + what can reasonably be done without live servers?
    - since we take DNS_RESOLVER in environ, can always point it at a local
      fake resolver which returns stuff on localhost for all results

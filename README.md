## mrt-nom

Parser and tooling for working with MRT files in Rust: https://datatracker.ietf.org/doc/html/rfc6396

## Principles and Goals

* Correct and precise parsing of MRT and related protocols
  * Distinctions matter, but not everyone cares about all of them
* Fast and concurrent for individual files as well as across multiple files
  * Expect to be multi-core and cluster distributed from the beginning
* Clean and simple to use for those new to BGP level networking
  * Be able to answer most common questions simply and easily without domain knowledge
* Extensible and embeddable for those already familiar with the domain
  * If a component can be valuable on its own, make it easy to do so
  * Library first, service application next
* Low level library interface for protocol parsing
* High level long running service for network and business level event handling

## Development Progress

- [ ] v0.1 Correct parsing of MRT full view, and update files
  - [ ] First full MRT view parsed into Enums and Structs
  - [ ] First update MRT file parsed into Enums and Structs
  - [ ] Tests written for file level parsing, as well as subcomponent parsing
  - [ ] Benchmarks in place for:
    - [ ] parsing from local compressed file
	- [ ] parsing from uncompressed buffer
  - [ ] Example usage for initial base use cases:
    - [ ] Full parse of view and update MRT files
	- [ ] Given ASN return IP Blocks announced, with and without routes
	- [ ] Given IP address return all routes visible
	- [ ] Given ASN and multiple update files return changes(Add/Delete/Change) for ASN between update files
- [ ] v0.2 Performance enhancement focus for given usage examples
- [ ] v0.3 Documentation focus
- [ ] v0.4 Long running service with events
- [ ] v1.0 Simple to deploy as a part of a larger SaaS service



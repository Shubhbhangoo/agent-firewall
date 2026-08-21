# Changelog

All notable changes to Agent Firewall are documented here.

## [0.3.0] - 2026-08-21

### Added

- Identity-aware policy enforcement
- Agent-specific policy matching
- Identity and argument condition combinations
- Policy specificity testing
- Identity policy conflict testing
- MCP argument security testing
- Argument type security testing
- Policy mutation security testing
- Policy reload testing
- Concurrent request testing
- Performance benchmarks
- Expanded adversarial security test coverage

### Security

- Hardened policy precedence handling
- Strongest applicable restriction continues to win:
  `allow < approval < deny`
- Added exact agent identity matching
- Added validation for policy identity values
- Hardened payment argument validation
- Added protection against malformed and unexpected argument types
- Added MCP boundary attack tests
- Added path traversal and tool-name variation tests
- Added fail-closed behavior coverage

### Testing

The v0.3.0 test suite contains:

**145 passing tests**

Coverage includes:

- Policy enforcement
- Policy validation
- Policy conflicts
- Policy precedence
- Policy specificity
- Agent identity
- Identity conflicts
- Identity + argument policies
- MCP enforcement
- MCP argument attacks
- Argument type attacks
- Policy mutation
- Policy reload behavior
- Concurrency
- Performance

### Performance

Development benchmark results:

```text
1000 requests:       ~0.56 seconds
1000 mixed requests: ~0.66 seconds
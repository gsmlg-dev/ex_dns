# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `ex_dns`, a pure Elixir DNS library that provides DNS protocol message parsing, zone management, and resource record handling. The library implements DNS message formats, resource records, and zone operations according to DNS RFC standards.

## Development Commands

### Testing
```bash
mix test                                  # Run all tests
mix test test/dns/message_test.exs       # Run specific test file
mix test --include wip                    # Run tests including WIP tagged tests
mix test --trace                         # Run tests with detailed output
```

### Code Quality & Analysis
```bash
mix format                               # Format code with Elixir formatter
mix format --check-formatted            # Check if code is formatted
mix credo                               # Run static code analysis
mix dialyzer                            # Run type checking and static analysis
```

### Build & Dependencies
```bash
mix deps.get                            # Install/update dependencies
mix compile                             # Compile the project
mix clean                               # Clean compiled files
mix compile --warnings-as-errors        # Treat warnings as errors (CI requirement)
```

### Documentation
```bash
mix docs                                # Generate documentation
mix help                                # List available tasks
```

### Publishing & Release
```bash
mix publish                             # Format and publish to hex.pm (custom alias)
mix hex.publish --yes                   # Direct publish to hex.pm
```

### Manual Testing Scripts
```bash
elixir test_all_string_chars.exs        # Test all record type String.Chars implementations
elixir test_zone_system.exs            # Test zone management functionality
```

## Architecture Overview

The codebase follows a modular structure with clear separation of concerns:

### Core Components

**DNS.Message Protocol System**
- `DNS.Parameter` protocol handles binary serialization/deserialization
- `String.Chars` protocol provides human-readable string representations
- All DNS entities implement both protocols for consistent behavior

**DNS.Message Hierarchy**
- `DNS.Message` - Top-level DNS message with header, questions, and record sections
- `DNS.Message.Header` - Message header (ID, flags, counts)
- `DNS.Message.Question` - Query section with QNAME, QTYPE, QCLASS
- `DNS.Message.Record` - Resource records with name, type, class, TTL, and data
- `DNS.Message.Record.Data/*` - 20+ specific record type implementations (A, AAAA, CNAME, MX, TXT, DNSSEC records, etc.)
- `DNS.Message.Domain` - Domain name parsing with compression support
- `DNS.Message.EDNS0` - Extension mechanisms and options

**DNS.Zone Management**
- `DNS.Zone` - Zone abstraction supporting 4 types: :authoritative, :stub, :forward, :cache
- `DNS.Zone.Manager` - CRUD operations and zone lifecycle management
- `DNS.Zone.Store` - ETS-based persistent zone storage
- `DNS.Zone.Cache` - TTL-based caching with automatic expiration
- `DNS.Zone.Loader` - Zone file loading from various sources
- `DNS.Zone.FileParser` - BIND format zone file parsing
- `DNS.Zone.Validator` - Zone validation and diagnostics
- `DNS.Zone.DNSSEC` - DNSSEC signing and validation (basic implementation)

### Key Implementation Patterns

**Protocol-Based Architecture**
All DNS entities implement `DNS.Parameter.to_iodata/1` for binary serialization and `String.Chars.to_string/1` for display. This provides consistent behavior across the entire library.

**Binary Pattern Matching**
Heavy use of Elixir's pattern matching on binaries for efficient DNS protocol parsing, particularly in domain name compression and record data parsing.

**ETS-Based Storage**
Zone management uses ETS tables for in-memory storage with separate tables for zone data and metadata, supporting high-concurrency access patterns.

**Type System Integration**
Comprehensive use of `@type` specifications throughout the codebase with proper union types and structured error returns.

### Critical Implementation Details

**Domain Name Compression**
Located in `DNS.Message.Domain.parse_domain_from_message/2` - handles DNS message compression with pointer dereferencing. This is a performance-critical path and security-sensitive area.

**Record Data Dispatch**
`DNS.Message.Record.Data` uses pattern matching on record type integers to dispatch to appropriate record type modules. New record types require adding entries in multiple places.

**Zone Manager Store Integration**
`DNS.Zone.Manager` coordinates with `DNS.Zone.Store` for persistence and `DNS.Zone.Cache` for temporary storage, with automatic initialization and cleanup.

**Error Handling Patterns**
The codebase uses a mix of throw/1 for parsing errors and {:error, reason} tuples for validation errors. This inconsistency is being addressed in ongoing refactoring.

### Security Considerations

**Domain Compression Depth**
Domain name decompression in `DNS.Message.Domain` is vulnerable to compression loop attacks. Implementation must include depth limits.

**Binary Data Validation**
Record length fields (rdlength) require validation to prevent memory exhaustion attacks. Critical in `DNS.Message.Record.from_iodata/2`.

**DNSSEC Implementation**
Current DNSSEC support uses placeholder cryptographic functions. Production use requires proper cryptographic implementations.

## File Organization

- `lib/dns/` - Core DNS implementation
  - `message/` - DNS protocol message handling
  - `zone/` - Zone management operations
- `test/dns/` - Comprehensive test suite matching lib structure
- `priv/data/` - DNS root hints and zone data files
- `test_*_string_chars.exs` - Manual testing scripts for protocol implementations
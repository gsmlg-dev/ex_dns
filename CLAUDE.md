# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `ex_dns`, a pure Elixir DNS library that provides DNS protocol message parsing, zone management, and resource record handling. The library implements DNS message formats, resource records, and zone operations according to DNS RFC standards.

## Architecture

The codebase follows a modular structure with these key components:

- **DNS.Message**: Core DNS message structure with Header, Question, Record sections
- **DNS.Zone**: Zone management for authoritative, stub, forward, and cache zones
- **DNS.ResourceRecordType**: DNS record type definitions (A, AAAA, CNAME, MX, etc.)
- **DNS.Class**: DNS class definitions (IN, CH, HS, etc.)
- **DNS.Parameter**: Protocol serialization/deserialization interface

### Key Module Structure

```
DNS/
├── Message/           # DNS message format implementation
│   ├── Header.ex      # Message header (ID, flags, counts)
│   ├── Question.ex    # Question section
│   ├── Record.ex      # Resource record format
│   ├── Record/Data/   # Specific record types (A, AAAA, CNAME, etc.)
│   └── EDNS0.ex       # Extension mechanisms for DNS
├── Zone/             # DNS zone management
│   ├── Name.ex       # Zone name handling
│   ├── RootHint.ex   # Root server hints
│   └── RRSet.ex      # Resource record sets
└── Class.ex          # DNS class definitions
```

## Development Commands

### Testing
```bash
mix test                    # Run all tests
mix test test/path/to/file_test.exs  # Run specific test file
```

### Code Quality
```bash
mix format                  # Format code with Elixir formatter
mix credo                   # Run static code analysis
mix dialyzer               # Run type checking and static analysis
```

### Documentation
```bash
mix docs                   # Generate documentation
mix help                   # List available tasks
```

### Publishing
```bash
mix publish                # Format and publish to hex.pm
```

## Key Patterns

- **Protocol Implementation**: Uses `DNS.Parameter` protocol for binary serialization
- **String Representation**: Uses `String.Chars` protocol for human-readable output
- **Data Structures**: Immutable structs for all DNS entities
- **Error Handling**: Returns structured data with validation
- **Zone Types**: Supports :authoritative, :stub, :forward, :cache zone types

## File Organization

- `lib/dns/` - Core DNS implementation
- `test/dns/` - Corresponding test files
- `priv/data/` - DNS root hints and zone data
- `doc/` - Generated documentation
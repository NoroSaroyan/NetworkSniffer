# Documentation Index - NetworkSniffer

Quick reference guide to all NetworkSniffer documentation.

## Main Entry Points

- **[README.md](../README.md)** - Project overview, quick start, and key features
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and component interactions

## Component Documentation

### For Users
- **[USAGE.md](USAGE.md)** - Building, deploying, and using all components
  - Prerequisites and installation
  - Component-by-component usage guide
  - Deployment scenarios
  - Troubleshooting

### For Developers
- **[API_REFERENCE.md](API_REFERENCE.md)** - Code documentation and APIs
  - Sniffer component API
  - Server component overview
  - GUI client architecture
  - Protocol definitions

- **[DEVELOPMENT.md](DEVELOPMENT.md)** - Development setup and contribution guide
  - IDE setup
  - Build system details
  - Code organization
  - Testing approach
  - Debugging guide

## Technical References

- **[PROTOCOL.md](PROTOCOL.md)** - Network communication protocol specification
  - Binary frame format
  - Message types
  - Handshake sequences
  - Communication flows

- **[BPF_GUIDE.md](BPF_GUIDE.md)** - Berkeley Packet Filter technical reference
  - System call reference
  - ioctl commands
  - Performance characteristics
  - Platform details

## Organization Structure

### Root Level
```
NetworkSniffer/
├── README.md              ← Start here!
├── src/                   ← Source code
├── docs/                  ← All documentation
├── build/                 ← Build output
├── CMakeLists.txt
└── Makefile
```

### Documentation Hierarchy

```
README.md (Project overview)
    ├── ARCHITECTURE.md (System design)
    │   ├── API_REFERENCE.md (Code APIs)
    │   ├── PROTOCOL.md (Network protocol)
    │   └── BPF_GUIDE.md (BPF details)
    │
    ├── USAGE.md (How to use)
    │   ├── Building
    │   ├── Configuration
    │   └── Troubleshooting
    │
    └── DEVELOPMENT.md (For developers)
        ├── Setup
        ├── Build system
        ├── Code organization
        └── Testing
```

## Quick Navigation

### I want to...

**Get started quickly**
→ [README.md - Quick Start](../README.md#quick-start)

**Build and deploy**
→ [USAGE.md - Building](USAGE.md#building-the-project)

**Understand the architecture**
→ [ARCHITECTURE.md - Overview](ARCHITECTURE.md#high-level-system-architecture)

**See API documentation**
→ [API_REFERENCE.md](API_REFERENCE.md)

**Learn about the network protocol**
→ [PROTOCOL.md](PROTOCOL.md)

**Set up development environment**
→ [DEVELOPMENT.md - Setup](DEVELOPMENT.md#development-environment-setup)

**Troubleshoot issues**
→ [USAGE.md - Troubleshooting](USAGE.md#troubleshooting)

**Contribute code**
→ [DEVELOPMENT.md - Contributing](DEVELOPMENT.md#contributing)

## Documentation Statistics

| Document | Purpose | Size |
|----------|---------|------|
| README.md | Project overview | ~5 KB |
| ARCHITECTURE.md | System design | ~28 KB |
| API_REFERENCE.md | Code APIs | ~14 KB |
| USAGE.md | User guide | ~13 KB |
| DEVELOPMENT.md | Developer guide | ~16 KB |
| PROTOCOL.md | Network spec | ~19 KB |
| BPF_GUIDE.md | Technical reference | ~15 KB |
| **Total** | **Complete documentation** | **~110 KB** |

## Maintenance Notes

- All documentation uses Markdown format for easy versioning
- Cross-references use relative paths for portability
- Code examples are tested and verified
- Links are verified during documentation updates

## Version History

- **2024-12-25**: Complete documentation consolidation and reorganization
  - Merged class-specific docs into API_REFERENCE.md
  - Renamed BPF_INTEGRATION.md → BPF_GUIDE.md
  - Renamed NETWORKING.md → PROTOCOL.md
  - Enhanced USAGE.md with comprehensive guide
  - Added DEVELOPMENT.md for contributors
  - Removed obsolete documentation files
  - Created professional README.md

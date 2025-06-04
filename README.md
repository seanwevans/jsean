[📝 Read The RFC here!](https://seanwevans.github.io/jsean/)

# JSean - Secure and Role-Based JSON Data Structure

## Overview
JSean (JSON Security Enhanced Access Notation) is a secure, JSON-compatible data structure designed to enhance data protection, granular access control, and versioning. The system integrates AES-256 encryption, role-based access control (RBAC), and schema validation to ensure compliance with GDPR, HIPAA, and SOX standards.

## Features
- **Field-Level Encryption**: AES-256-GCM encryption ensures sensitive fields are secured at the data level.
- **Role-Based Access Control (RBAC)**: Hierarchical roles govern field visibility and modification rights.
- **Schema Validation**: Fields are validated according to defined schema types, including integer ranges and string patterns.
- **Versioning and Auditing**: Supports snapshots and delta versions to track data history and enable rollback functionality.

## Key Components
### C Implementation (`jsean.c`)
- Defines data structures for schema fields, data entries, and versions.
- AES-GCM encryption and decryption for field-level protection.
- Permission-based access to data fields.
- Example program demonstrating encrypted field storage and retrieval with RBAC enforcement.

## Getting Started
1. Make sure the OpenSSL development headers are available on your system. On
   Debian/Ubuntu you can install them with:
   ```bash
   sudo apt-get install libssl-dev
   ```
2. Compile the `jsean.c` file using `gcc` and link against OpenSSL:
   ```bash
   gcc -o jsean jsean.c -lcrypto
   ```

## Running the Example
Execute the compiled binary to see the demo interaction:
```bash
./jsean
```
The output shows encryption of selected fields and permission checks.

> **Note**: This code is a prototype meant for demonstration only and is not
> production ready.

## License
Copyright (c) 2024 Sean Evans. All rights reserved.


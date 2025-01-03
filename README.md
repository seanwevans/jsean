# JSean - Secure and Role-Based JSON Data Structure

## Overview
JSean (JSON Security Enhanced Access Notation) is a secure, JSON-compatible data structure designed to enhance data protection, granular access control, and versioning. The system integrates AES-256 encryption, role-based access control (RBAC), and schema validation to ensure compliance with GDPR, HIPAA, and SOX standards.

## Project Structure
```
- index.js       # JavaScript logic for dynamic Table of Contents and text bolding
- jsean.c        # Core C implementation for encrypted field storage and schema validation
- rfc.html       # RFC-style document describing JSean's architecture, features, and use cases
- styles.css     # CSS styling for the RFC document
```

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

### JavaScript (`index.js`)
- Dynamically generates Table of Contents for the RFC document.
- Applies bold styling to "JSean" occurrences in the document.

### HTML (`rfc.html`)
- RFC-style specification outlining the design goals, architecture, and implementation guidelines for JSean.
- Includes sections on encryption, access control, schema validation, and versioning.

### CSS (`styles.css`)
- Provides consistent styling for the RFC document, including tables, headers, code blocks, and notes.

## Getting Started
1. Compile the `jsean.c` file:
   ```bash
   gcc -o jsean jsean.c -lcrypto
   ```
2. Open `rfc.html` in a browser to review the project documentation.
3. Modify `index.js` or `styles.css` to customize the appearance and behavior of the RFC document.

## Requirements
- OpenSSL (for AES encryption in `jsean.c`)
- Modern web browser (for RFC HTML document)

## License
Copyright (c) 2024 Sean Evans. All rights reserved.


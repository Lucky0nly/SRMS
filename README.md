# Student Management System (Refactored)

A secure, robust, and feature-rich Student Management System written in ANSI C.

## Features

- **Secure Authentication**: Uses SHA-256 hashing with per-user salts.
- **Role-Based Access Control (RBAC)**:
  - **ADMIN**: Full access (Add, Delete, Search, View).
  - **STAFF**: Limited access (Add, Search, View).
  - **GUEST**: Read-only access (Search, View).
- **Safe Input Handling**: Uses `fgets` and input parsing to prevent buffer overflows (replaces `scanf`).
- **Atomic File Operations**: Updates are written to a temporary file and renamed to prevent data corruption.
- **Password Masking**: Passwords are not echoed to the console during entry.
- **Robustness**: Handles malformed lines and empty inputs gracefully.

## Build Instructions

No external libraries are required (just the standard C library).

```bash
gcc -o srms main.c
```

## Running the Application

```bash
./srms
```

## First Run / Default Credentials

If `credentials.txt` does not exist, the system will automatically create a default admin account:

- **Username**: `admin`
- **Password**: `admin`

**IMPORTANT**: Change this password immediately by editing `credentials.txt` with a new hash or using a management tool (not included in this single-file distribution).

## File Formats

### `students.csv`
Stored as `Roll,Name,Marks`.
```csv
101,John Doe,85.50
102,Jane Smith,92.00
```

### `credentials.txt`
Stored as `Username:Salt:Hash:Role`.
- **Role** is one of: `ADMIN`, `STAFF`, `GUEST`.
- **Salt**: 16-character random string.
- **Hash**: 64-character SHA-256 hex string of `salt + password`.

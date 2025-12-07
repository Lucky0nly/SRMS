# Credentials Migration Guide

The updated Student Management System uses a secure hashed format for credentials. You must migrate your existing plaintext `credentials.txt` to the new format.

## Old Format
```text
username:password
```

## New Format
```text
username:salt:hash:role
```
- **salt**: A random 16-character string.
- **hash**: SHA-256 hash of the string `salt + password`.
- **role**: One of `ADMIN`, `STAFF`, `GUEST`.

## Migration Utilities

Since manually calculating SHA-256 hashes is difficult, you can use the following Python script to generate valid entries for your `credentials.txt`.

### Python Helper Script (`migrate.py`)

Save this code as `migrate.py` and run it to generate a line for `credentials.txt`.

```python
import hashlib
import secrets
import string

def generate_entry(username, password, role):
    # Generate 16-char salt
    alphabet = string.ascii_letters + string.digits
    salt = ''.join(secrets.choice(alphabet) for i in range(16))
    
    # Calculate Hash (SHA256 of salt + password)
    combined = salt + password
    pass_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    
    return f"{username}:{salt}:{pass_hash}:{role}"

# Example Usage
print(generate_entry("admin", "admin", "ADMIN"))
print(generate_entry("staff1", "staffpass", "STAFF"))
print(generate_entry("guest1", "guestpass", "GUEST"))
```

### Manual Migration Steps

1.  Backup your old `credentials.txt`.
2.  Delete or empty `credentials.txt`.
3.  Run the python script above for each user you want to add.
4.  Copy the output lines into `credentials.txt`.

Example `credentials.txt` content:
```text
admin:AbCd1234EfGh5678:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:ADMIN
staff:XyZ98765QWERtyui:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:STAFF
```

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

print(generate_entry("admin", "admin123", "ADMIN"))
print(generate_entry("staff", "staff666", "STAFF"))
print(generate_entry("guest", "guest111", "GUEST"))
print(generate_entry("user", "user123", "GUEST")) # Mapping USER to GUEST as per logic

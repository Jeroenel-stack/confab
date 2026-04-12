# add_agent.py
import sqlite3
import hashlib

print("="*50)
print("🛡️ COMMAND CENTER: SECURE AGENT REGISTRATION")
print("="*50)

# Ask the Admin for the new agent's details
new_username = input("Enter new Agent Username (e.g., agent_bravo): ")
new_password = input("Enter new Agent Password: ")

# Hash the password using SHA-256 (Fulfilling Requirement 1)
hashed_password = hashlib.sha256(new_password.encode()).hexdigest()

# Connect to the database and insert the new agent
conn = sqlite3.connect('intelligence.db')
c = conn.cursor()

try:
    c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'agent')", 
              (new_username, hashed_password))
    
    # Add a note to the Audit Log
    c.execute("INSERT INTO audit_logs (action) VALUES (?)", 
              (f"ADMIN COMMAND: New operative registered -> {new_username}",))
    
    conn.commit()
    print(f"\n✅ SUCCESS: Operative '{new_username}' has been granted secure access.")
except Exception as e:
    print(f"\n❌ ERROR: Failed to add agent. ({e})")
finally:
    conn.close()
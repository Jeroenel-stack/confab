import sqlite3

print("="*50)
print("💀 ENEMY BREACH DETECTED: ACCESSING DATABASE...")
print("="*50)

conn = sqlite3.connect('intelligence.db')
c = conn.cursor()

# We changed this line to grab the NEWEST report instead of the oldest!
c.execute("SELECT id, agent_name FROM reports ORDER BY id DESC LIMIT 1")
target = c.fetchone()

if not target:
    print("No reports found to tamper with! Tell an agent to submit one first.")
else:
    target_id = target[0]
    target_agent = target[1]
    
    print(f"Targeting newest report submitted by: {target_agent} (ID: {target_id})")
    print("Injecting malicious data into the Integrity Hash...")
    
    # The hacker changes the stored hash to something fake
    fake_hash = "malicious_fake_hash_99999999999999999999"
    
    c.execute("UPDATE reports SET integrity_hash = ? WHERE id = ?", (fake_hash, target_id))
    conn.commit()
    
    print("💀 MISSION ACCOMPLISHED: Database corrupted. Leaving without a trace.")

conn.close()
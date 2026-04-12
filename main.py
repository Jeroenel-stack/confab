# main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# Security Libraries
import hashlib          # For Requirement 1
import secrets          # For Requirement 4
from cryptography.fernet import Fernet  # For Requirement 3

app = FastAPI()

# ==========================================
# SECURITY IMPLEMENTATIONS
# ==========================================

# [REQUIREMENT 4]: Secure password/token generation using `secrets`
# Instead of a weak, hardcoded password, we generate a cryptographically strong 16-character token when the server starts.
GENERATED_ROOM_TOKEN = secrets.token_urlsafe(16)
print("="*50)
print(f"🚨 ADMIN ALERT: The secure room token is: {GENERATED_ROOM_TOKEN}")
print("Give this token to users so they can log in.")
print("="*50)

# [REQUIREMENT 1]: Password hashing using `hashlib`
# We never store the plain-text token in our verification variable. We hash it with SHA-256.
ROOM_TOKEN_HASH = hashlib.sha256(GENERATED_ROOM_TOKEN.encode()).hexdigest()

# Setup for [REQUIREMENT 3]: Data Encryption and Decryption
# We generate a symmetric encryption key. The server uses this to lock and unlock messages.
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)


# ==========================================
# WEBSOCKET CONNECTION MANAGER
# ==========================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()


# ==========================================
# CORE APPLICATION LOGIC
# ==========================================
@app.websocket("/ws/{username}/{token}")
async def websocket_endpoint(websocket: WebSocket, username: str, token: str):
    await websocket.accept()
    
    # [REQUIREMENT 2]: Login Authentication System
    # 1. Hash the token the user provided in the login screen.
    provided_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # 2. Compare the user's hash with the server's stored hash.
    if provided_hash != ROOM_TOKEN_HASH:
        await websocket.send_text("System: Invalid Token. Access Denied.")
        await websocket.close()
        return

    # If authentication passes, let them in!
    await manager.connect(websocket)
    await manager.broadcast(f"🟢 {username} joined the secure chat.")
    
    try:
        while True:
            # Receive plain text from the user
            raw_data = await websocket.receive_text()
            
            # [REQUIREMENT 3]: Data Encryption and Decryption
            # A. ENCRYPT the data before doing anything with it (simulating secure storage/processing)
            encrypted_data = cipher_suite.encrypt(raw_data.encode())
            
            # Print the encrypted gibberish to the terminal (Great for your live demo!)
            print(f"\n🔒 ENCRYPTED MESSAGE FROM {username}:")
            print(encrypted_data)
            
            # B. DECRYPT the data so it can be broadcasted securely to other authenticated users
            decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
            
            # Send the decrypted text to the chat room
            await manager.broadcast(f"**{username}**: {decrypted_data}")
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(f"🔴 {username} left the chat.")

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
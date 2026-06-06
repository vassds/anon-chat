import json
import uuid
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import ed25519
from database_setup import SessionLocal, init_db, UserNode, FeedMessage

app = FastAPI(title="Zero-Knowledge Router Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, alias: str, websocket: WebSocket):
        self.active_connections[alias] = websocket

    def disconnect(self, alias: str):
        if alias in self.active_connections:
            del self.active_connections[alias]

    async def broadcast(self, message: dict):
        payload = json.dumps(message)
        for ws in list(self.active_connections.values()):
            try:
                await ws.send_text(payload)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/feed")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    db = SessionLocal()
    alias = None
    try:
        initial_auth = await websocket.receive_text()
        auth_data = json.loads(initial_auth)
        
        alias = auth_data.get("alias")
        ed25519_pub_hex = auth_data.get("ed25519_pubkey")
        dh_pub_hex = auth_data.get("dh_pubkey")
        intent = auth_data.get("intent") 
        
        if not alias or not ed25519_pub_hex or not intent:
            await websocket.close(code=4000)
            return

        challenge_nonce = str(uuid.uuid4())
        await websocket.send_text(json.dumps({"type": "challenge", "nonce": challenge_nonce}))
        
        response_raw = await websocket.receive_text()
        response_data = json.loads(response_raw)
        signature_hex = response_data.get("signature")

        pubkey_bytes = bytes.fromhex(ed25519_pub_hex)
        verify_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        
        try:
            verify_key.verify(bytes.fromhex(signature_hex), challenge_nonce.encode('utf-8'))
        except Exception as e:
            print(f"[!] Auth Failed for {alias}: {e}")
            await websocket.close(code=4001)
            return

        # Strict Database Verification Logic
        user = db.query(UserNode).filter(UserNode.alias == alias).first()
        
        if intent == "login":
            if not user:
                print(f"[DEBUG] ❌ Rejected Login: Identity {alias} does not exist.")
                await websocket.send_text(json.dumps({"type": "auth_error", "message": "Identity not found. Please register first."}))
                await websocket.close(code=4004)
                return
            else:
                print(f"[DEBUG] ✅ Successful Login for {alias}")
                
        elif intent == "register":
            if user:
                print(f"[DEBUG] ⚠️ Registration Warning: Identity {alias} already exists. Proceeding as login.")
            else:
                user = UserNode(alias=alias, ed25519_pubkey=ed25519_pub_hex, dh_pubkey=dh_pub_hex)
                db.add(user)
                db.commit()
                print(f"[DEBUG] ✅ New Identity Registered: {alias}")

        await manager.connect(alias, websocket)

        history = db.query(FeedMessage).order_by(FeedMessage.created_at.desc()).limit(50).all()
        history.reverse()
        
        historical_payloads = [{
            "type": "feed_message",
            "sender_alias": msg.sender_alias,
            "encryption_metadata": json.loads(msg.encryption_metadata),
            "ciphertext": msg.ciphertext,
            "signature": msg.signature,
            "timestamp": msg.created_at.isoformat()
        } for msg in history]
        
        await websocket.send_text(json.dumps({"type": "history", "messages": historical_payloads}))

        # X-RAY DEBUGGING LOOP
        while True:
            try:
                data_raw = await websocket.receive_text()
                msg_data = json.loads(data_raw)
                print(f"\n[DEBUG] 1. Received from React: {msg_data}")
                
                metadata = msg_data.get("encryption_metadata")
                ciphertext = msg_data.get("ciphertext")
                signature = msg_data.get("signature")
                
                if not metadata or not ciphertext or not signature:
                    print("[DEBUG] ❌ Error: Missing fields in the payload.")
                    continue

                try:
                    verify_key.verify(bytes.fromhex(signature), ciphertext.encode('utf-8'))
                    print("[DEBUG] 2. Cryptographic Signature Valid!")
                except Exception as e:
                    print(f"[DEBUG] ❌ Error: Invalid Signature! Dropping message. Details: {e}")
                    continue

                new_msg = FeedMessage(
                    sender_alias=alias,
                    encryption_metadata=json.dumps(metadata),
                    ciphertext=ciphertext,
                    signature=signature
                )
                db.add(new_msg)
                db.commit()
                print("[DEBUG] 3. Successfully saved to PostgreSQL!")

                await manager.broadcast({
                    "type": "feed_message",
                    "sender_alias": alias,
                    "encryption_metadata": metadata,
                    "ciphertext": ciphertext,
                    "signature": signature
                })
                print("[DEBUG] 4. Broadcasted message to all connected clients!")

            except Exception as e:
                print(f"[DEBUG] ❌ FATAL LOOP CRASH: {e}")
                break

    except WebSocketDisconnect:
        if alias:
            manager.disconnect(alias)
    finally:
        db.close()
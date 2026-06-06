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
        except Exception:
            await websocket.close(code=4001)
            return

        user = db.query(UserNode).filter(UserNode.alias == alias).first()
        
        if intent == "login" and not user:
            await websocket.send_text(json.dumps({"type": "auth_error", "message": "Identity not found. Please register first."}))
            await websocket.close(code=4004)
            return
        elif intent == "register" and not user:
            user = UserNode(alias=alias, ed25519_pubkey=ed25519_pub_hex, dh_pubkey=dh_pub_hex)
            db.add(user)
            db.commit()

        await manager.connect(alias, websocket)

        # Include msg_id in the history fetch
        history = db.query(FeedMessage).order_by(FeedMessage.created_at.desc()).limit(50).all()
        history.reverse()
        
        historical_payloads = [{
            "type": "feed_message",
            "msg_id": msg.msg_id,
            "sender_alias": msg.sender_alias,
            "encryption_metadata": json.loads(msg.encryption_metadata),
            "ciphertext": msg.ciphertext,
            "signature": msg.signature,
        } for msg in history]
        
        await websocket.send_text(json.dumps({"type": "history", "messages": historical_payloads}))

        # EVENT LISTENER LOOP
        while True:
            try:
                data_raw = await websocket.receive_text()
                msg_data = json.loads(data_raw)
                action = msg_data.get("action", "post")

                # Handle Posting a New Message
                if action == "post":
                    msg_id = msg_data.get("msg_id")
                    metadata = msg_data.get("encryption_metadata")
                    ciphertext = msg_data.get("ciphertext")
                    signature = msg_data.get("signature")
                    
                    if not msg_id or not metadata or not ciphertext or not signature:
                        continue

                    try:
                        # Verify signature over msg_id + ciphertext
                        verify_key.verify(bytes.fromhex(signature), (msg_id + ciphertext).encode('utf-8'))
                    except Exception as e:
                        print(f"Signature mismatch on post: {e}")
                        continue

                    new_msg = FeedMessage(
                        msg_id=msg_id,
                        sender_alias=alias,
                        encryption_metadata=json.dumps(metadata),
                        ciphertext=ciphertext,
                        signature=signature
                    )
                    db.add(new_msg)
                    db.commit()

                    await manager.broadcast({
                        "type": "feed_message",
                        "msg_id": msg_id,
                        "sender_alias": alias,
                        "encryption_metadata": metadata,
                        "ciphertext": ciphertext,
                        "signature": signature
                    })

                # Handle Deleting an Existing Message
                elif action == "delete":
                    msg_id = msg_data.get("msg_id")
                    signature = msg_data.get("signature")

                    try:
                        # Verify the user actually signed the intent to delete THIS specific message
                        verify_key.verify(bytes.fromhex(signature), f"delete_{msg_id}".encode('utf-8'))
                    except Exception as e:
                        print(f"Signature mismatch on delete: {e}")
                        continue

                    # Ensure the user is the original author of the post before deleting
                    msg_to_delete = db.query(FeedMessage).filter(FeedMessage.msg_id == msg_id, FeedMessage.sender_alias == alias).first()
                    if msg_to_delete:
                        db.delete(msg_to_delete)
                        db.commit()
                        
                        # Tell all connected clients to remove this message from their screens instantly
                        await manager.broadcast({
                            "type": "message_deleted",
                            "msg_id": msg_id
                        })

            except Exception:
                break

    except WebSocketDisconnect:
        if alias:
            manager.disconnect(alias)
    finally:
        db.close()
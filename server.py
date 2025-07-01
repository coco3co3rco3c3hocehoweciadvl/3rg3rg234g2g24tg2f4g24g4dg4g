from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime
import sqlite3
from passlib.context import CryptContext
from typing import List, Optional

app = FastAPI()

# Database setup
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
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

conn.commit()

# Password hashing
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

@app.post("/register")
async def register_user(user: User):
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
    cursor.execute(
        'SELECT username, password FROM users WHERE username = ?', (user.username,)
    )
    db_user = cursor.fetchone()
    if db_user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    stored_username, stored_password = db_user
    if user.username == stored_username and pwd_context.verify(user.password, stored_password):
        return {"success": True}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/send_message")
async def send_message(message: Message):
    cursor.execute(
        'INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
        (message.sender, message.receiver, message.message)
    )
    conn.commit()
    return {"success": True}

@app.get("/get_chat_history/{user1}/{user2}")
async def get_chat_history(user1: str, user2: str, limit: int = 50):
    cursor.execute('''
        SELECT sender, receiver, message, timestamp
        FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp DESC LIMIT ?
    ''', (user1, user2, user2, user1, limit))
    messages = []
    for row in reversed(cursor.fetchall()):
        messages.append({
            'sender': row[0],
            'receiver': row[1],
            'message': row[2],
            'timestamp': row[3]
        })
    return {"messages": messages}

@app.post("/add_friend")
async def add_friend(friend_request: FriendRequest):
    try:
        cursor.execute(
            'INSERT INTO friends (user1, user2, status) VALUES (?, ?, ?)',
            (friend_request.user1, friend_request.user2, 'accepted')
        )
        conn.commit()
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
    return {"friends": [row[0] for row in cursor.fetchall()]}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

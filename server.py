import socket
import threading
import json
import time
from datetime import datetime
import hashlib
import sqlite3
import os

class MessengerServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.clients = {}
        self.user_status = {}
        self.init_database()

    def init_database(self):
        self.conn = sqlite3.connect('messenger.db', check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS friends (
                id INTEGER PRIMARY KEY,
                user1 TEXT NOT NULL,
                user2 TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password, email=''):
        try:
            hashed_password = self.hash_password(password)
            self.cursor.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                (username, hashed_password, email)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def authenticate_user(self, username, password):
        hashed_password = self.hash_password(password)
        self.cursor.execute(
            'SELECT username FROM users WHERE username = ? AND password = ?',
            (username, hashed_password)
        )
        return self.cursor.fetchone() is not None

    def search_users(self, query, current_user):
        self.cursor.execute(
            'SELECT username FROM users WHERE username LIKE ? AND username != ?',
            (f'%{query}%', current_user)
        )
        return [row[0] for row in self.cursor.fetchall()]

    def get_user_friends(self, username):
        self.cursor.execute('''
            SELECT CASE
                WHEN user1 = ? THEN user2
                ELSE user1
            END as friend
            FROM friends
            WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'
        ''', (username, username, username))
        return [row[0] for row in self.cursor.fetchall()]

    def add_friend(self, user1, user2):
        try:
            self.cursor.execute(
                'INSERT INTO friends (user1, user2, status) VALUES (?, ?, ?)',
                (user1, user2, 'accepted')
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def save_message(self, sender, receiver, message):
        self.cursor.execute(
            'INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
            (sender, receiver, message)
        )
        self.conn.commit()

    def get_chat_history(self, user1, user2, limit=50):
        self.cursor.execute('''
            SELECT sender, receiver, message, timestamp
            FROM messages
            WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
            ORDER BY timestamp DESC LIMIT ?
        ''', (user1, user2, user2, user1, limit))
        messages = []
        for row in reversed(self.cursor.fetchall()):
            messages.append({
                'sender': row[0],
                'receiver': row[1],
                'message': row[2],
                'timestamp': row[3]
            })
        return messages

    def handle_client(self, client_socket, address):
        username = None
        try:
            while True:
                data = client_socket.recv(1024).decode('utf-8')
                if not data:
                    break
                try:
                    message = json.loads(data)
                    msg_type = message.get('type')
                    if msg_type == 'register':
                        success = self.register_user(
                            message['username'],
                            message['password'],
                            message.get('email', '')
                        )
                        response = {'type': 'register_response', 'success': success}
                        client_socket.send(json.dumps(response).encode('utf-8'))
                    elif msg_type == 'login':
                        username = message['username']
                        if self.authenticate_user(username, message['password']):
                            self.clients[username] = client_socket
                            self.user_status[username] = 'online'
                            friends = self.get_user_friends(username)
                            friends_status = {
                                friend: self.user_status.get(friend, 'offline')
                                for friend in friends
                            }
                            response = {
                                'type': 'login_response',
                                'success': True,
                                'friends': friends_status
                            }
                            self.notify_friends_status(username, 'online')
                        else:
                            response = {'type': 'login_response', 'success': False}
                        client_socket.send(json.dumps(response).encode('utf-8'))
                    elif msg_type == 'search_users':
                        if username:
                            users = self.search_users(message['query'], username)
                            response = {'type': 'search_results', 'users': users}
                            client_socket.send(json.dumps(response).encode('utf-8'))
                    elif msg_type == 'add_friend':
                        if username:
                            success = self.add_friend(username, message['friend'])
                            if success:
                                self.update_friends_list(username)
                                if message['friend'] in self.clients:
                                    self.update_friends_list(message['friend'])
                            response = {'type': 'add_friend_response', 'success': success}
                            client_socket.send(json.dumps(response).encode('utf-8'))
                    elif msg_type == 'get_chat_history':
                        if username:
                            history = self.get_chat_history(username, message['friend'])
                            response = {
                                'type': 'chat_history',
                                'friend': message['friend'],
                                'messages': history
                            }
                            client_socket.send(json.dumps(response).encode('utf-8'))
                    elif msg_type == 'message':
                        if username:
                            receiver = message['receiver']
                            msg_text = message['message']
                            self.save_message(username, receiver, msg_text)
                            if receiver in self.clients:
                                msg_data = {
                                    'type': 'new_message',
                                    'sender': username,
                                    'message': msg_text,
                                    'timestamp': datetime.now().strftime('%H:%M')
                                }
                                self.clients[receiver].send(json.dumps(msg_data).encode('utf-8'))
                except json.JSONDecodeError:
                    print(f"Invalid JSON from {address}")
                except Exception as e:
                    print(f"Error handling client {address}: {e}")
        finally:
            if username:
                if username in self.clients:
                    del self.clients[username]
                self.user_status[username] = 'offline'
                self.notify_friends_status(username, 'offline')
            client_socket.close()

    def notify_friends_status(self, username, status):
        friends = self.get_user_friends(username)
        for friend in friends:
            if friend in self.clients:
                try:
                    msg = {
                        'type': 'friend_status',
                        'friend': username,
                        'status': status
                    }
                    self.clients[friend].send(json.dumps(msg).encode('utf-8'))
                except:
                    pass

    def update_friends_list(self, username):
        if username in self.clients:
            friends = self.get_user_friends(username)
            friends_status = {
                friend: self.user_status.get(friend, 'offline')
                for friend in friends
            }
            msg = {
                'type': 'friends_update',
                'friends': friends_status
            }
            try:
                self.clients[username].send(json.dumps(msg).encode('utf-8'))
            except:
                pass

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print(f"🚀 Server started on {self.host}:{self.port}")
        print("Waiting for connections...")
        try:
            while True:
                client_socket, address = server_socket.accept()
                print(f"✅ Client connected: {address}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
        finally:
            server_socket.close()
            self.conn.close()

if __name__ == "__main__":
    server = MessengerServer()
    server.start_server()

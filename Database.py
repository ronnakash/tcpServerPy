import os
import sqlite3
from sqlite3 import Error
import uuid

class User():
    def __init__(self, username, uuid):
        self.username = username
        self.uuid = uuid

class File():
    def __init__(self, uuid, filename, path):
        self.filename = filename
        self.path = path
        self.uuid = uuid

class Database: 

    def __init__(self):
        self.path = os.path.join("Server.db")
        self.connection = None
        self.connection = sqlite3.connect(self.path)
        self.cursor = self.connection.cursor()
        createClientTable = """
            CREATE TABLE IF NOT EXISTS clients (
                id UUID PRIMARY KEY,
                username varcahr(127) UNIQUE NOT NULL,
                public_key varchar(160),
                last_seen timestamp,
                aes_key varchar(256)
            );"""

        createFilesTable = """
            CREATE TABLE IF NOT EXISTS files (
                id UUID,
                file_name varcahr(255) NOT NULL,
                path_name varchar(255),
                verified bit
            );"""
        self.cursor.execute(createClientTable)
        self.connection.commit()
        self.cursor.execute(createFilesTable)
        self.connection.commit()

    def saveUser(self, user : User):
        insertValues = (user.username, user.uuid)
        newUserQuery = '''INSERT INTO clients(username, id) VALUES(?, ?)'''
        self.cursor.execute(newUserQuery, insertValues)
        self.connection.commit()

    def getUserByUsername(self, username):
        query = '''SELECT * FROM clients WHERE username=?'''
        data = (username,)
        self.cursor.execute(query, data)
        row = self.cursor.fetchall()[0]
        user = User(row[1], row[0])
        return user

    def getUserById(self, userId):
        query = '''SELECT * FROM clients WHERE id=?'''
        data = (userId,)
        self.cursor.execute(query, data)
        row = self.cursor.fetchall()[0]
        return User(row[1], userId)

    def updateUserAesKey(self, username, key):
        query = '''
            UPDATE clients
            SET aes_key = ?
            WHERE username = ?
        '''
        params = (key, username)
        self.cursor.execute(query, params,)
        self.connection.commit()

    def updateUserPublicRsaKey(self, username, key):
        query = '''
            UPDATE clients
            SET public_key = ?
            WHERE username = ?
        '''
        params = (username, key, )
        self.cursor.execute(query, params)
        self.connection.commit()

    def updateUserLastLogin(self, username):
        query = '''
            UPDATE clients
            SET last_seen = CURRENT_TIMESTAMP
            WHERE username = ?
        '''
        params = (username,)
        self.cursor.execute(query, params)
        self.connection.commit()

    def getUsersAesKeyById(self, cid):
        query = '''SELECT * FROM clients WHERE id=?'''

        params = (cid,)
        self.cursor.execute(query, params)
        row = self.cursor.fetchall()[0]
        return row[4]


    def newFile(self, file : File):
        query = '''
        INSERT INTO files (id, file_name, path_name)
        VALUES (?,?,?)
        '''
        params = (file.uuid, file.filename, file.path)
        self.cursor.execute(query, params)
        self.connection.commit()

    def updateFileVerification(self, filename, bool):
        bit = int(bool)
        query = '''
            UPDATE files
            SET verified = ?
            WHERE file_name = ?
        '''
        params = (bit, filename)
        self.cursor.execute(query, params)
        self.connection.commit()


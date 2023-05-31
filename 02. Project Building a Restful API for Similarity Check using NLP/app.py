# Importing flask module
# An object of Flask class is our WSGI application.
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import json

# Flask constructor takes the name of
# current module (__name__) as argument.
app = Flask(__name__)
api = Api(app)

# client = MongoClient("mogodb://db:27017")
client = MongoClient("mongodb://localhost:27017")
db = client.SimilarityDB
users = db["Users"]


def hash_password(password):
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt)


def verifyPw(userName, password):
    hashedPassword = users.find_one({"Username": userName})[
        "Password"].encode('utf-8')
    pwd_bytes = password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hashedPassword)


def countTokens(userName):
    numTokens = users.find_one({"Username": userName})["Tokens"]
    return numTokens


def userExist(userName):
    if users.find_one({"Username": userName}):
        return True
    return False


class Register(Resource):
    def post(self):
        # Getting the json data from the request
        postedData = request.get_json()

        # Getting the data
        userName = postedData["Username"]
        password = postedData["Password"]

        # Encrypt the password
        hashedPassword = hash_password(password=password)
        hashedPassword_str = str(hashedPassword)

        if not postedData:
            return jsonify({"error": "No data"})

        # Checking if the user already exists
        if userExist(userName):
            retJson = {
                "status": 301,
                "message": "User already exists"
            }
            return jsonify(retJson)

        else:
            # Inserting the data into the database
            record = {
                "Username": userName,
                "Password": hashedPassword.decode('utf-8'),
                "Tokens": 6
            }

            users.insert_one(record)
            retJson = {
                "Status": 200,
                "message": "You have successfully signed up for API"
            }
            return jsonify(retJson)


class Detect(Resource):
    def post(self):
        # Getting the json data from the request
        postedData = request.get_json()

        # Getting the data
        userName = postedData["Username"]
        password = postedData["Password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        # Verify the username
        if not userExist(userName):
            retJson = {
                "status": 301,
                "message": "Invalid username"
            }
            return jsonify(retJson)

        # Verify the password
        correctPw = verifyPw(userName, password)

        if not correctPw:
            retJson = {
                "status": 302,
                "message": "Invalid password"
            }
            return jsonify(retJson)

        # Verify user has enough tokens
        numTokens = countTokens(userName)
        if numTokens <= 0:
            retJson = {
                "status": 303,
                "message": "You don't have enough tokens, please refill!"
            }
            return jsonify(retJson)

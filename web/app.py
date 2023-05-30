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
db = client.SentencesDatabase
users = db["Users"]


def hash_password(password):
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt)


def verifyPw(userName, password):
    # if user not in self.data:
    # return False
    hashedPassword = users.find_one({"Username": userName})[
        "Password"].encode('utf-8')
    pwd_bytes = password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hashedPassword)


def countTokens(userName):
    numTokens = users.find_one({"Username": userName})["Tokens"]
    return numTokens


class Register(Resource):
    def post(self):
        # Getting the json data from the request
        postedData = request.get_json()

        # Get the data
        userName = postedData["Username"]
        password = postedData["Password"]

        # Encrypt the password
        hashedPassword = hash_password(password=password)
        hashedPassword_str = str(hashedPassword)

        if not postedData:
            return jsonify({"error": "No data"})

        # Checking if the user already exists
        if users.find_one({"Username": userName}):
            return jsonify({"message": "User already exists"})

        else:
            # Inserting the data into the database
            record = {
                "Username": userName,
                "Password": hashedPassword.decode('utf-8'),
                "Sentence": "",
                "Tokens": 6
            }

            dumpVar = json.dumps(record)
            loadVar = json.loads(dumpVar)

            users.insert_one(loadVar)
            retJson = {
                "Status": 200,
                "message": "You have successfully signed up for API"
            }
            return jsonify(retJson)


class Store(Resource):
    def post(self):
        # Getting the json data from the request
        postedData = request.get_json()

        userName = postedData["Username"]
        password = postedData["Password"]
        sentence = postedData["Sentence"]

        # Verify the password
        correctPw = verifyPw(userName, password)

        if not correctPw:
            retJson = {
                "status": 302,
                "message": "You have entered wrong credentials"
            }
            return jsonify(retJson)

        # Verify user has enough tokens
        numTokens = countTokens(userName)
        if numTokens <= 0:
            retJson = {
                "status": 301,
                "message": "You don't have enough tokens"
            }
            return jsonify(retJson)

        # store the sentence
        users.update_one({
            "Username": userName
        }, {
            "$set": {
                "Sentence": sentence,
                "Tokens": numTokens-1
            }
        })
        retJson = {
            "status": 200,
            "message": "Sentence saved successfully."
        }
        return jsonify(retJson)


class Get(Resource):
    def get(self):
        # Getting the json data from the request
        postedData = request.get_json()

        userName = postedData["Username"]
        password = postedData["Password"]
        sentence = postedData["Sentence"]

        # Verify the password
        correctPw = verifyPw(userName, password)

        if not correctPw:
            retJson = {
                "status": 302,
                "message": "You have entered wrong credentials"
            }
            return jsonify(retJson)

        # Verify user has enough tokens
        numTokens = countTokens(userName)
        if numTokens <= 0:
            retJson = {
                "status": 301,
                "message": "You don't have enough tokens"
            }
            return jsonify(retJson)

        # Return the sentence
        sentence = users.find_one({"Username": userName})["Sentence"]
        retJson = {
            "status": 200,
            "sentence": sentence
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Get, '/get')


if __name__ == "__main__":
    app.run(host='0.0.0.0')

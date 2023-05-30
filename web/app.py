# Importing flask module
# An object of Flask class is our WSGI application.
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

# Flask constructor takes the name of
# current module (__name__) as argument.
app = Flask(__name__)
api = Api(app)


client = MongoClient("mogodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]


def hash_password(self, password):
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt)


def verifyPw(userName, password):
    # if user not in self.data:
    # return False
    hashPassword = users.find_one({"Username": userName})[0]["Password"]
    pwd_bytes = password.encode("utf-8")
    return bcrypt.checkpw(pwd_bytes, hashPassword)


def countTokens(userName):
    countTokens = users.find_one({"Username": userName})[0]["Tokens"]


class Register(Resource):
    def post(self):
        # Getting the json data from the request
        PostedData = request.get_json()

        userName = PostedData["Username"]
        password = PostedData["Password"]
        hashPassword = hash_password(password=password)

        # Checking if the user already exists
        if users.find_one({"Username": userName}):
            return jsonify({"message": "User already exists"}), 400
        else:
            # Inserting the data into the database
            users.insert_one({"Username": userName, "Password": hashPassword})
            retJson = {
                "Status": 200,
                "message": "You have successfully signed up for API"
            }
            return jsonify(retJson), 201


class Store(Resource):
    def post(self):
        # Getting the json data from the request
        PostedData = request.get_json()

        userName = PostedData["Username"]
        password = PostedData["Password"]
        sentence = PostedData["Sentence"]

        correctPw = verifyPw(userName, password)

        if not correctPw:
            retJson = {
                "status": 302
            }
            return jsonify(retJson)


api.add_resource(Register, '/register')

if __name__ == "__main__":
    app.run(host='0.0.0.0')

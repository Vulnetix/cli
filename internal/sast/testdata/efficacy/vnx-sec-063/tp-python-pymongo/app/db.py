from pymongo import MongoClient

~>MONGO_URI = 'mongodb://reporting:@@sample:[A-Za-z0-9]{20}@@@10.1.2.3:27017/admin'
client = MongoClient(MONGO_URI)

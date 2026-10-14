import boto3

~>BEDROCK_API_KEY = "ABSKQmVkcm9ja0FQSUtleS@@sample:[A-Za-z0-9+/]{140}@@=="

def client():
    return boto3.client("bedrock-runtime")

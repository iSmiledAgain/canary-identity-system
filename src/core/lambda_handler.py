import json

def handler(event, context):
    """
    Temporary handler for AWS Lambda. 
    Person B will expand this module to invoke the analyzer and alerting tools.
    """
    print("Canary Event Received:")
    print(json.dumps(event))
    return {
        "statusCode": 200,
        "body": json.dumps("Canary Event Processed Successfully")
    }
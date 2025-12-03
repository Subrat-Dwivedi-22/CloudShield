import os
import json
import boto3
import numpy as np
import joblib
from datetime import datetime

# AWS Clients
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
ssm = boto3.client("ssm")

# Environment Variables
MODEL_BUCKET = os.environ["MODEL_BUCKET"]
MODEL_KEY = os.environ["MODEL_KEY"]
DDB_TABLE = os.environ["DDB_TABLE"]
SNS_ARN = os.environ["SNS_ARN"]

model = None
table = None

def load_model():
    global model, table

    if model is None:
        local_path = "/tmp/model.joblib"
        print("[MODEL] Loading model from S3:", MODEL_BUCKET, MODEL_KEY)
        s3.download_file(MODEL_BUCKET, MODEL_KEY, local_path)
        model = joblib.load(local_path)
        print("[MODEL] Loaded successfully")

    if table is None:
        table = dynamodb.Table(DDB_TABLE)
        print("[DDB] Connected to DynamoDB table:", DDB_TABLE)

    return model


def block_attacker(instance_id, ip):
    print(f"[BLOCK] Blocking IP {ip} on instance {instance_id}")

    command = f"sudo iptables -I INPUT -s {ip} -j DROP"
    print("[BLOCK] Executing command:", command)

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
            TimeoutSeconds=30
        )

        command_id = response["Command"]["CommandId"]
        print("[BLOCK] SSM Command Sent! Command ID:", command_id)
        return command_id

    except Exception as e:
        print("[BLOCK ERROR] Failed:", e)
        return None


def lambda_handler(event, context):

    print("\n======================")
    print("RAW EVENT:", event)
    print("======================\n")

    model = load_model()

    # Allow both direct and SQS events
    if "Records" in event:
        body = json.loads(event["Records"][0]["body"])
    else:
        body = event

    # Validate instance ID
    instance_id = body.get("instance_id")
    if not instance_id:
        print("[ERROR] Missing instance_id in event")
        return {"statusCode": 400, "body": "Missing instance_id"}

    source_ip = body.get("source_ip", "unknown")

    # --- UPDATE STARTS HERE ---
    # Extract required features (UPDATED FOR V2 MODEL)
    features = [
        "bytes_sent", "packets", "login_attempts",
        "failed_logins", "duration_s", "dst_port",
        "sudo_attempts",   # <--- ADDED
        "files_deleted"    # <--- ADDED
    ]
    # --- UPDATE ENDS HERE ---

    X = np.array([[float(body.get(f, 0)) for f in features]])

    # ML Decision
    score = float(model.decision_function(X)[0])
    print("[ML] Score:", score)

    if score < -0.05:
        action = "BLOCK"
    elif score < 0:
        action = "ALERT"
    else:
        action = "OK"


    print(f"[RESULT] Action = {action}, IP = {source_ip}")

    # Log to DynamoDB
    timestamp = str(datetime.utcnow())
    table.put_item(Item={
        "instance_id": instance_id,
        "source_ip": source_ip,
        "timestamp": timestamp,
        "score": str(score),
        "action": action
    })

    # SNS ONLY FOR BLOCK
    if action == "BLOCK":
        print("[SNS] Sending BLOCK alert...")
        sns.publish(
            TopicArn=SNS_ARN,
            Subject="🚨 AgenticAI IDS: IP BLOCKED",
            Message=(
                f"Instance: {instance_id}\n"
                f"Attacker IP: {source_ip}\n"
                f"Score: {score}\n"
                f"Action: BLOCK"
            )
        )

        # Execute block
        cmd_id = block_attacker(instance_id, source_ip)

        # Log block execution
        table.put_item(Item={
            "instance_id": instance_id,
            "source_ip": source_ip,
            "timestamp": timestamp + "_block",
            "score": str(score),
            "action": "BLOCK_EXECUTED",
            "ssm_command_id": cmd_id
        })

    return {
        "statusCode": 200,
        "body": json.dumps({"action": action, "score": score})
    }


import json, logging, boto3, os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
s3  = boto3.client("s3")
iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
QUARANTINE_SG_ID = os.environ.get("QUARANTINE_SG_ID")

def isolate_ec2(instance_id):
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[QUARANTINE_SG_ID]
        )
        return f"EC2 instance {instance_id} isolated successfully"
    except Exception as e:
        return f"EC2 isolation failed for {instance_id}: {e}"


def restrict_s3(bucket):
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        return f"S3 bucket {bucket} restricted successfully"
    except Exception as e:
        return f"S3 restriction failed for {bucket}: {e}"

def disable_iam_user(username):
    try:
        iam.update_login_profile(
            UserName=username,
            PasswordResetRequired=True
        )
        return f"IAM user {username} disabled temporarily"
    except Exception as e:
        return f"IAM disable failed for {username}: {e}"

def lambda_handler(event, context):
    findings = event.get("detail", {}).get("findings", [])
    if not findings:
        logger.info("No findings found in event")
        return {"status": "no-findings"}

    results = []

    for f in findings:
        title = f.get("Title", "Unknown")
        severity = f.get("Severity", {}).get("Label", "UNKNOWN")
        description = f.get("Description", "")
        resources = f.get("Resources", [])
        resource_type = resources[0].get("Type", "Unknown") if resources else "Unknown"
        resource_id = resources[0].get("Id", "Unknown") if resources else "Unknown"

        logger.info(f"Processing finding: {title} ({severity}) on {resource_type}:{resource_id}")

        #resource type for case-insensitive match
        rt = resource_type.lower()


        if "ec2" in rt:
            action = isolate_ec2(resource_id)
        elif "s3" in rt:
            action = restrict_s3(resource_id)
        elif "iam" in rt:
            action = disable_iam_user(resource_id)
        else:
            action = f"No remediation defined for {resource_type}"

        logger.info(f"Action result: {action}")

        result = {
            "Title": title,
            "Severity": severity,
            "ResourceType": resource_type,
            "ResourceId": resource_id,
            "ActionTaken": action,
            "Description": description
        }
        results.append(result)

    try:
        if SNS_TOPIC_ARN:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="Real Automated Response Executed",
                Message=json.dumps(results, indent=2)
            )
            logger.info("SNS alert sent successfully.")
        else:
            logger.warning("SNS_TOPIC_ARN not configured.")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

    return {"status": "actions-executed", "count": len(results)}

import boto3, json

guardduty = boto3.client('guardduty')
cloudwatch = boto3.client('cloudwatch')

def numeric_to_label(sev):
    try:
        value = float(sev)
    except Exception:
        return None
    if value >= 9:
        return "CRITICAL"
    if value >= 7:
        return "HIGH"
    if value >= 4:
        return "MEDIUM"
    return "LOW"

def lambda_handler(event, context):
    try:
        # Getting the detector
        detectors = guardduty.list_detectors().get('DetectorIds', [])
        if not detectors:
            print("No GuardDuty detectors found in this region.")
            return {"status": "no-detector"}
        detector_id = detectors[0]

        finding_ids = []
        paginator = guardduty.get_paginator('list_findings')
        for page in paginator.paginate(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}}
        ):
            ids = page.get('FindingIds', [])
            if ids:
                finding_ids.extend(ids)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        if finding_ids:
            for i in range(0, len(finding_ids), 50):
                chunk = finding_ids[i:i+50]
                resp = guardduty.get_findings(DetectorId=detector_id, FindingIds=chunk)
                findings = resp.get('Findings', [])
                for f in findings:
                    label = f.get('SeverityLabel')
                    if not label:
                        label = numeric_to_label(f.get('Severity'))
                    if label not in counts:
                        label = numeric_to_label(f.get('Severity')) or "LOW"
                    counts[label] += 1
        else:
            print("No active findings found. Counts will be zero.")

        print("GuardDuty severity summary:", counts)

        # publish metrics
        metric_payload = []
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            metric_payload.append({
                'MetricName': f'ActiveFindingsCount_{level}',
                'Value': counts[level],
                'Unit': 'Count'
            })

        cloudwatch.put_metric_data(
            Namespace='Custom/ThreatDashboard',
            MetricData=metric_payload
        )

        print("Published metrics to CloudWatch")
        return {"status": "success", "counts": counts}

    except Exception as e:
        print("Error:", str(e))
        return {"status": "error", "message": str(e)}

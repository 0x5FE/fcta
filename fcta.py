import boto3
from google.cloud import securitycenter
from azure.mgmt.security import SecurityCenter
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from sklearn.ensemble import IsolationForest

    # Integration with Cloud Providers APIs
 def get_aws_findings(access_key, secret_key):
     session = boto3.session.Session(
     aws_access_key_id=access_key,
     aws_secret_access_key=secret_key,
     region_name="us-east-1",
    )    
    client = session.client("securityhub")
    paginator = client.get_paginator("get_findings")
    response_iterator = paginator.paginate()
    findings = []
    for page in response_iterator:
        findings.extend(page["Findings"])
    return findings

    def normalize_aws_findings(findings):
        for finding in findings:
            finding["timestamp"] = datetime.fromtimestamp(finding["CreatedAt"])
            finding["source"] = "AWS"
            finding["type"] = finding["FindingProviderFields"]["Type"]
            finding["threat_actor"] = finding["FindingProviderFields"]["ThreatActorName"]
        return findings  

    def get_gcp_findings(credentials):
        client = securitycenter.SecurityCommandCenterClient(credentials=credentials)
        findings = client.list_findings(
            parent="organizations/1234567890",
            filter="state=ACTIVE",
        )
        return findings

    def normalize_gcp_findings(findings):
        for finding in findings:
            finding["timestamp"] = finding.create_time.ToDatetime()
            finding["source"] = "GCP"
            finding["type"] = finding.finding_class
            finding["threat_actor"] = finding.threat_actor_name
        return findings

    def get_azure_findings(credentials):
        client = SecurityCenter(credentials=credentials)
        findings = client.alerts.list()
        return findings

    def normalize_azure_findings(findings):
        for finding in findings:
            finding["timestamp"] = finding.properties.created_time
            finding["source"] = "Azure"
            finding["type"] = finding.properties.alert_type
            finding["threat_actor"] = finding.properties.threat_intelligence.threat_actor_name
        return findings 

    #event processing
    def normalize_events(events):
        for event in events:
            event["timestamp"] = datetime.fromtimestamp(event["timestamp"])
        return events

    def enrich_events(events, threat_intel_feed):
        for event in events:
            # Extract relevant attributes from the event (e.g., IP addresses, URLs)
            indicators = extract_indicators(event)

            # Check indicators against threat intelligence feed
            for indicator in indicators:
                threat_info = threat_intel_feed.get(indicator, None)
                if threat_info:
                event["threat_intelligence"] = threat_info
                # Update event severity or other attributes based on threat info

            return events

    def extract_indicators(event):

        indicators = []
        # You can customize this based on the data available in your events
        if "source_ip" in

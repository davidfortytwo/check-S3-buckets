import boto3
import json

KNOWN_GROUP_URIS = ["http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "http://acs.amazonaws.com/groups/global/AllUsers"]
TOO_PERMISSIVE_PERMISSIONS = ["WRITE", "WRITE_ACP", "FULL_CONTROL"]

# Initialize a session using DigitalOcean Spaces.
session = boto3.Session(
    region_name="us-east-1",
    aws_access_key_id="ACCESS_KEY",
    aws_secret_access_key="SECRET_KEY"
)

s3_client = session.client('s3'use_ssl=True)

# Initialize an empty list to store any issues found
permission_issues = []

# ASVS Requirement 3.1.1: Verify that all S3 bucket policies are set to "Deny all" unless explicitly needed
# Iterate through all S3 buckets and check the policy
for bucket in s3_client.list_buckets()['Buckets']:
    bucket_name = bucket['Name']
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy["Policy"])
        if "Statement" in policy_json:
            for statement in policy_json["Statement"]:
                if statement["Effect"] != "Deny":
                    permission_issues.append(f'Bucket {bucket_name} has a policy that allows access, expected "Deny"')
    except:
        permission_issues.append(f'Bucket {bucket_name} does not have a policy')

# ASVS Requirement 3.1.2: Verify that all S3 buckets have versioning enabled
# Iterate through all S3 buckets and check if versioning is enabled
for bucket in s3_client.list_buckets()['Buckets']:
    bucket_name = bucket['Name']
    versioning_status = s3_client.get_bucket_versioning(Bucket=bucket_name)
    if "Status" not in versioning_status or versioning_status["Status"] != "Enabled":
        permission_issues.append(f'Bucket {bucket_name} does not have versioning enabled')
        
# ASVS Requirement 3.1.3: Verify that all S3 bucket ACLs are set to "private" unless explicitly needed
# Iterate through all S3 objects and check the ACL
for bucket in s3_client.list_buckets()['Buckets']:
    bucket_name = bucket['Name']
    paginator = s3_client.get_paginator('list_objects_v2')
    for result in paginator.paginate(Bucket=bucket_name):
        if 'Contents' in result:
            for obj in result['Contents']:
                key = obj['Key']
                acl = s3_client.get_object_acl(Bucket=bucket_name, Key=key)
                    for grant in acl["Grants"]:
                      # Check if the grantee is a known group or user
                      if "URI" in grant["Grantee"]:
                        if grant["Grantee"]["URI"] in KNOWN_GROUP_URIS:
                            grantee = KNOWN_GROUP_URIS[grant["Grantee"]["URI"]]
                        else:
                            grantee = grant["Grantee"]["URI"]
                      elif "EmailAddress" in grant["Grantee"]:
                        grantee = grant["Grantee"]["EmailAddress"]
                      elif "ID" in grant["Grantee"]:
                        grantee = grant["Grantee"]["ID"]
                      else:
                        grantee = "Unknown"

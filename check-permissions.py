import os
import boto3
import argparse
import json
import html
import html2text
import weasyprint

KNOWN_GROUP_URIS = ["http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "http://acs.amazonaws.com/groups/global/AllUsers"]
TOO_PERMISSIVE_PERMISSIONS = ["WRITE", "WRITE_ACP", "FULL_CONTROL"]

# Initialize a session using DigitalOcean Spaces.
session = boto3.Session(
    region_name="us-east-1",
    aws_access_key_id="ACCESS_KEY",
    aws_secret_access_key="SECRET_KEY"
)

def main():
    # Initialize an empty list to store any issues found
    permission_issues = []

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Check S3 bucket policies and permissions')
    parser.add_argument('-o', '--output', choices=['pdf', 'txt', 'html'], help='Output format')
    # Perform input sanitization to prevent XSS and other injection attacks
    parser.replace("<", "&lt;").replace(">", "&gt;")
    args = parser.parse_args()

    # Initialize a session using DigitalOcean Spaces.
    #session = boto3.Session(
    #    region_name="us-east-1",
    #    aws_access_key_id="ACCESS_KEY",
    #    aws_secret_access_key="SECRET_KEY"
    #)

    s3_client = session.client('s3',use_ssl=True)

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
        
                        # Check if the grantee has too permissive permissions
                        if grant["Permission"] in TOO_PERMISSIVE_PERMISSIONS:
                            permission_issues.write(f"Bucket: {bucket_name}\n")
                            permission_issues.write(f"Grantee: {grantee}\n")
                            permission_issues.write(f"Permission: {grant['Permission']}\n")
                            permission_issues.write("\n")
                        
    # ASVS Requirement 3.1.4-1: Verify that all S3 bucket policies do not allow public write access
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy["Policy"])
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    # check if statement includes "s3:PutObject" or "s3:PutObjectAcl" actions
                    if "s3:PutObject" in statement["Action"] or "s3:PutObjectAcl" in statement["Action"]:
                        permission_issues.append(f'Bucket {bucket_name} has a policy that allows public write access')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a policy')
        
    # ASVS Requirement 3.1.4-2: Verify that all S3 bucket policies include a condition to limit access to specific IAM users or roles
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy["Policy"])
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    if "Condition" in statement:
                        if "ArnLike" in statement["Condition"] or "StringLike" in statement["Condition"]:
                            if "aws:PrincipalArn" in statement["Condition"]["ArnLike"] or "aws:PrincipalArn" in statement["Condition"]["StringLike"]:
                                pass
                            else:
                                permission_issues.append(f'Bucket {bucket_name} has a policy that does not limit access to specific IAM users or roles')
                        else:
                            permission_issues.append(f'Bucket {bucket_name} has a policy that does not limit access to specific IAM users or roles')
                    else:
                        permission_issues.append(f'Bucket {bucket_name} has a policy that does not limit access to specific IAM users or roles')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a policy')
        
        
    # ASVS Requirement 3.1.5: Verify that all S3 bucket policies include a condition to limit access to specific IP ranges or VPCs
    # Iterate through all S3 buckets and check the policy
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy["Policy"])
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    if "Condition" not in statement or ("IpAddress" not in statement["Condition"] and "ArnLike" not in statement["Condition"]):
                        permission_issues.append(f'Bucket {bucket_name} does not have a condition to limit access to specific IP ranges or VPCs')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a policy')
        
    # ASVS Requirement 3.1.6: Verify that all S3 buckets have MFA delete enabled
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        mfa_delete_status = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if "MFADelete" not in mfa_delete_status or mfa_delete_status["MFADelete"] != "Enabled":
            permission_issues.append(f'Bucket {bucket_name} does not have MFA delete enabled')
        
    # ASVS Requirement 3.1.7-1: Verify that all S3 bucket lifecycle rules are configured to transition objects to Amazon S3 Glacier or S3 Glacier Deep Archive after a certain number of days
    # Iterate through all S3 buckets and check the lifecycle configuration
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            lifecycle_config = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if "Rules" in lifecycle_config:
                for rule in lifecycle_config["Rules"]:
                    if "Transition" in rule:
                        transition_days = rule["Transition"]["Days"]
                        transition_storage_class = rule["Transition"]["StorageClass"]
                        if transition_storage_class not in ["GLACIER", "DEEP_ARCHIVE"]:
                            permission_issues.append(f'Bucket {bucket_name} has a lifecycle rule with an invalid transition storage class of {transition_storage_class}, expected "GLACIER" or "DEEP_ARCHIVE"')
                        if transition_days < 30:
                            permission_issues.append(f'Bucket {bucket_name} has a lifecycle rule with transition days less than 30, expected at least 30 days')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a lifecycle configuration')

        
    # ASVS Requirement 3.1.7-2: Verify that all S3 buckets have an S3 bucket lifecycle policy in place to automatically delete old or infrequently accessed objects
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            lifecycle_config = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if "Rules" not in lifecycle_config or len(lifecycle_config["Rules"]) == 0:
                permission_issues.append(f'Bucket {bucket_name} does not have a lifecycle policy')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a lifecycle policy')   

    # ASVS Requirement 3.1.7-3: Verify that all S3 bucket policies include a condition to limit access to specific request headers
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy["Policy"])
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    if "Condition" in statement:
                        if "ArnLike" in statement["Condition"]:
                            if "aws:Referer" not in statement["Condition"]["ArnLike"] and "aws:UserAgent" not in statement["Condition"]["ArnLike"]:
                                permission_issues.append(f'Bucket {bucket_name} does not have a condition to limit access to specific HTTP referers or user agents')
                        elif "StringLike" in statement["Condition"]:
                            if "aws:Referer" not in statement["Condition"]["StringLike"] and "aws:UserAgent" not in statement["Condition"]["StringLike"]:
                                permission_issues.append(f'Bucket {bucket_name} does not have a condition to limit access to specific HTTP referers or user agents')
                        elif "StringEquals" in statement["Condition"]:
                            if "aws:Referer" not in statement["Condition"]["StringEquals"] and "aws:UserAgent" not in statement["Condition"]["StringEquals"]:
                                permission_issues.append(f'Bucket {bucket_name} does not have a condition to limit access to specific HTTP referers or user agents')
                    else:
                        permission_issues.append(f'Bucket {bucket_name} does not have a condition element in policy statement')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a policy')


    # ASVS Requirement 3.1.7-4: Verify that all S3 bucket policies include a condition to limit access based on the presence of specific authentication headers.

    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy["Policy"])
            if "Statement" in policy_json:
                for statement in policy_json["Statement"]:
                    if "Condition" in statement:
                        if "StringLike" in statement["Condition"]:
                            if "aws:SecureTransport" not in statement["Condition"]["StringLike"]:
                                permission_issues.append(f'Bucket {bucket_name} does not limit access based on the presence of specific authentication headers')
        except:
            permission_issues.append(f'Bucket {bucket_name} does not have a policy')
                        
        
    # ASVS Requirement 3.1.8: Verify that all S3 bucket encryption is enabled
    # Iterate through all S3 buckets and check the encryption
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        encryption_status = s3_client.get_bucket_encryption(Bucket=bucket_name)
        if "ServerSideEncryptionConfiguration" not in encryption_status:
            permission_issues.append(f'Bucket {bucket_name} does not have encryption enabled')
        else:
            encryption_type = encryption_status["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            if encryption_type not in ["AES256", "aws:kms"]:
                permission_issues.append(f'Bucket {bucket_name} has an unsupported encryption type: {encryption_type}')
                    
                
    # ASVS Requirement 3.1.9: Verify that all S3 bucket logging is enabled
    # Iterate through all S3 buckets and check if logging is enabled
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" not in logging_status:
            permission_issues.append(f'Bucket {bucket_name} does not have logging enabled')
        else:
            log_bucket_name = logging_status["LoggingEnabled"]["TargetBucket"]
            log_bucket_acl = s3_client.get_bucket_acl(Bucket=log_bucket_name)
            # Check if the log bucket has proper access controls
            for grant in log_bucket_acl["Grants"]:
                if grant["Permission"] != "READ":
                    permission_issues.append(f'Bucket {log_bucket_name} has {grant["Permission"]} permission, expected "READ"')

    # ASVS Requirement 3.1.10: Verify that all S3 bucket access logging is enabled and that the logs are stored in a separate bucket with proper access controls

    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
    
        if "LoggingEnabled" not in logging_config:
            permission_issues.append(f'Bucket {bucket_name} does not have access logging enabled')
        else:
            log_bucket = logging_config["LoggingEnabled"]["TargetBucket"]
            log_prefix = logging_config["LoggingEnabled"]["TargetPrefix"]
            log_bucket_policy = s3_client.get_bucket_policy(Bucket=log_bucket)
            log_bucket_policy_json = json.loads(log_bucket_policy["Policy"])
        
            # Check if the log bucket has proper access controls
            if "Statement" in log_bucket_policy_json:
                for statement in log_bucket_policy_json["Statement"]:
                    if statement["Effect"] != "Deny":
                        permission_issues.append(f'Access logging for bucket {bucket_name} is stored in bucket {log_bucket} which does not have "Deny" policy')

    # Print any issues found
    if permission_issues:
        for issue in permission_issues:
            print(issue)
    else:
        print("No permission issues found.")
    
    if args.output:
        if args.output == 'pdf':
            pdf_file = 'permission_issues.pdf'
            weasyprint.HTML(string=permission_issues).write_pdf(pdf_file)
        elif args.output == 'txt':
            txt_file = 'permission_issues.txt'
            with open(txt_file, 'w') as f:
                for item in permission_issues:
                    f.write("%s\n" % item)
        elif args.output == 'html':
            html_file = 'permission_issues.html'
            with open(html_file,'w') as f:
                f.write('<html>')
                f.write('<body>')
                f.write('<table>')
                for item in permission_issues:
                    f.write('<tr>')
                    f.write('<td>')
                    f.write(item)
                    f.write('</td>')
                    f.write('</tr>')
                f.write('</table>')
                f.write('</body>')
                f.write('</html>')    

if __name__ == "__main__":
    main()            

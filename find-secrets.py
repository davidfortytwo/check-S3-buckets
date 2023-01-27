import boto3
import re
import os
import argparse
from tqdm import tqdm

# Create an S3 client
s3 = boto3.client('s3')

# Default list of regular expressions to match against
secrets = [r'password', r'secret']

# Create an argument parser
parser = argparse.ArgumentParser()

# Add -r option to allow for manual input of regular expressions
parser.add_argument('-r', '--regex', help='Regular expression to include in search')

# Parse the arguments
args = parser.parse_args()

if args.regex:
    secrets.append(args.regex)

# Get a list of all S3 buckets
response = s3.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]

# Iterate through each bucket
for bucket in tqdm(buckets):
    # Use the boto3 paginator to handle pagination for the list_objects_v2 method
    paginator = s3.get_paginator('list_objects_v2')
    for result in paginator.paginate(Bucket=bucket):
        for obj in result.get('Contents', []):
            # Download the object from S3
            s3.download_file(bucket, obj['Key'], obj['Key'])
            # Open the downloaded object
            with open(obj['Key'], 'r') as f:
                content = f.read()
                # Search for secrets in the object's content
                for secret in secrets:
                    if re.search(secret, content):
                        print(f'Found {secret} in {obj["Key"]}')
            # Remove the downloaded object after searching its content
            os.remove(obj['Key'])

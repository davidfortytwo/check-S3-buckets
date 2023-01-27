import boto3
import re
from tqdm import tqdm

# Create an S3 client
s3 = boto3.client('s3')

# List of regular expressions to match against
secrets = [r'password', r'secret']

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

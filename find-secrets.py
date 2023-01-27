import boto3
import os
import re
import argparse
import psutil
from tqdm import tqdm

# Create an S3 client
s3 = boto3.client('s3')

# List of regular expressions to match against
secrets = [
r'(?i)access_?key',
r'(?i)access_?token',
r'(?i)api_?key',
r'(?i)client_?id',
r'(?i)client_?secret',
r'(?i)credentials',
r'(?i)certificate',
r'(?i)dsa',
r'(?i)email',
r'(?i)encryption',
r'(?i)2fa',
r'(?i)mfa',
r'(?i)hashed_?password',
r'(?i)jwt',
r'(?i)md5',
r'(?i)nonce',
r'(?i)otp',
r'(?i)pgp',
r'(?i)password',
r'(?i)private_?key',
r'(?i)rsa',
r'(?i)salt',
r'(?i)secret',
r'(?i)secret_?key',
r'(?i)security',
r'(?i)sha1',
r'(?i)sha256',
r'(?i)ssh',
r'(?i)ssl',
r'(?i)token',
r'(?i)username',
r'(?i)user_?name'
]
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

# Check for IAM user has access to the s3 bucket
try:
    for bucket in buckets:
        s3.head_bucket(Bucket=bucket)
except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] == "403":
        print(f"Access Denied: User does not have access to {bucket}")
        buckets.remove(bucket)


# Get the total size of all objects in all buckets
total_size = 0
for bucket in buckets:
    paginator = s3.get_paginator('list_objects_v2')
    for result in paginator.paginate(Bucket=bucket):
        for obj in result.get('Contents', []):
            total_size += obj['Size']

# Function to check if there is enough disk space for the objects
def check_disk_space(objects, required_space):
    """
    Function to check if there is enough disk space for the objects
    """
    disk_usage = psutil.disk_usage("/")
    free_space = disk_usage.free

    # if the amount of free space is less than the required space
    if free_space < required_space:
        raise ValueError("Not enough disk space. Required: {} bytes. Available: {} bytes.".format(required_space, free_space))
    
    # loop through the objects and check if they can fit on the disk
    for obj in objects:
        if obj.size > free_space:
            raise ValueError("Object '{}' is too large to fit on the disk. Required: {} bytes. Available: {} bytes.".format(obj.name, obj.size, free_space))
    
    print("There is enough disk space for the objects.")

# Create a secrets.txt file for storing found secrets
with open('secrets.txt', 'w') as secrets_file:
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
                        with open("secrets.txt", "a") as f:
                        f.write(f'Found {secret} in {obj["Key"]}\n')
            # Remove the downloaded object after searching its content
            os.remove(obj['Key'])

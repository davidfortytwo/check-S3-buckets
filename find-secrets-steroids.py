import boto3
import re
import os
import argparse
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Create an S3 client
s3 = boto3.client('s3',use_ssl=True,config=boto3.session.Config(signature_version='s3v4'))

# Get a list of all S3 buckets
response = s3.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-r', '--regex', help='Add a regular expression to search for')
parser.add_argument('-w', '--wordlist', help='Add a wordlist file to search for')
parser.add_argument('-p', '--password', help='Encryption password')
args = parser.parse_args()

# Add the manually entered regex to the list of secrets if provided
if args.regex:
    secrets = [args.regex]
else:
    secrets = [r’(?i)password’, r’(?i)secret’, r’(?i)security’, r’(?i)api_?key’, r’(?i)access_?key’, r’(?i)secret_?key’, r’(?i)private_?key’, r’(?i)token’, r’(?i)credentials’, r’(?i)certificate’, r’(?i)ssh’]

# Add the wordlist file to the list of secrets if provided
if args.wordlist:
    with open(args.wordlist, 'r') as f:
        secrets += f.read().splitlines()

# Encrypt the communications if a password is provided
if args.password:
    password = args.password.encode()
    salt = b'\xfa\x03\xee\x1b\x97\x9d\xea\x0e\x9f\x94\x03\x0c\x8f\x9c\x9e\x1b'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    # Encrypt the bucket and object names
    buckets = [f.encrypt(bucket.encode()) for bucket in buckets]

# Keep track of unencrypted objects
unencrypted_objects = []

# Iterate through each bucket
for bucket in tqdm(buckets):
    # Use the boto3 paginator to handle pagination for the list_objects_v2 method
    paginator = s3.get_paginator('list_objects_v2')
    for result in paginator.paginate(Bucket=bucket):
        for obj in result.get('Contents', []):
            # check if the object is encrypted in S3
            object_metadata = s3.head_object(Bucket=bucket, Key=obj['Key'])
            encryption_type = object_metadata.get('ServerSideEncryption')
            if encryption_type is None:
                unencrypted_objects.append(obj['Key'])
                print(f'Unencrypted object detected at {obj["Key"]}')
                continue
            # Download the object from S3
            s3.download_file(bucket, obj['Key'], obj['Key'])
            # Open the downloaded object
            with open(obj['Key'], 'r') as f:
                content = f.read()
                # Search for secrets in the object's content
                for secret in secrets + wordlist:
                    if re.search(secret, content):
                        print(f'Found {secret} in {obj["Key"]}')
            # Remove the downloaded object after searching its content
            os.remove(obj['Key'])

# save unencrypted objects list to file
if unencrypted_objects:
    with open('unencrypted_objects.txt', 'w') as f:
        f.write('\n'.join(unencrypted_objects))

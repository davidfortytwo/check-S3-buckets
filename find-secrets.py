import re

# List of regular expressions to match against
secrets = [r'password', r'secret']

# Open the file containing the S3 objects
with open('s3_objects.txt', 'r') as f:
    s3_objects = f.readlines()

# Iterate through each object and search for secrets
for obj in s3_objects:
    obj = obj.strip()
    for secret in secrets:
        if re.search(secret, obj):
            print(f'Found {secret} in {obj}')

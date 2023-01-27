import boto3

# Create an S3 client
s3 = boto3.client('s3')

# Get a list of all S3 buckets
response = s3.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]

# Open a file to write the objects
with open('s3_objects.txt', 'w') as f:
    # Iterate through each bucket and list all objects
    for bucket in buckets:
        f.write(f"Objects in bucket: {bucket}\n")
        # Use the boto3 paginator to handle pagination for the list_objects_v2 method
        paginator = s3.get_paginator('list_objects_v2')
        for result in paginator.paginate(Bucket=bucket):
            for obj in result.get('Contents', []):
                f.write(obj['Key'] + '\n')
        f.write('\n')

print("S3 objects listed in s3_objects.txt file")

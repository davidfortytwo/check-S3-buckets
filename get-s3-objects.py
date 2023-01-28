import boto3
import logging

# Create a logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Create a file handler
file_handler = logging.FileHandler("get_s3_objects.log")
file_handler.setLevel(logging.INFO)

# Create a formatter and add it to the file handler
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)


# Create an S3 client with the IAM role of the instance
s3 = boto3.client('s3')

logger.info("Starting to list S3 buckets")
# Get a list of all S3 buckets
response = s3.list_buckets()
buckets = [bucket['Name'] for bucket in response['Buckets']]
logger.info("Finished listing S3 buckets")

# Open a file to write the objects
try:
    # Open a file to write the objects
    with open("get-s3-objects.txt", 'w') as f:
        # Iterate through each bucket and list all objects
        for bucket in buckets:
            logger.info(f"Starting to list objects in {bucket}")
            # Use the boto3 paginator to handle pagination for the list_objects_v2 method
            paginator = s3.get_paginator('list_objects_v2')
            for result in paginator.paginate(Bucket=bucket):
                for obj in result.get('Contents', []):
                    f.write(obj['Key'] + '\n')
            logger.info(f"Finished listing objects in {bucket}")
except IOError as e:
    logger.error("An error occurred while opening or writing to the file: " + str(e))
        
finally:
    file_handler.close() 

# check-S3-buckets

# Installation

* Install boto3 and argparse by running the following command:

  pip install boto3 argparse

* Create a file containing the list of key names you want to check, with one key name per line. Let's call this file keys.txt for the purpose of these instructions.
* Set up your AWS credentials, this can be done by creating a new IAM user with programmatic access and s3 read access and configure the credentials in your local machine by following the instructions in this link https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
* Run the script by providing the appropriate values for the command-line arguments.

  python script.py -f keys.txt -r us-west-2 -b my-bucket -k key-name

* You can replace us-west-2 with the appropriate region code for your S3 bucket, and my-bucket with the actual name of your S3 bucket.

* The script will check each key name in the keys.txt file and print the url of the object if it exists and print the error if the object doesn't exist.


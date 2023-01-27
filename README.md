# check-S3-buckets

# Installation

* Install all dependencies by running this command:

  pip install -r requiements.txt

* Create a file containing the list of key names you want to check, with one key name per line. 

* You can generate a s3_objects.txt file containing list all the objects in all the S3 buckets in the account the script is being run with, by running the get-s3-objects.py script.

* Set up your AWS credentials, this can be done by creating a new IAM user with programmatic access and s3 read access and configure the credentials in your local machine by following the instructions in this link https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

* Set up your proxy server, For example if you are using Burp Suite, you need to configure it to listen on the right interface, and configure the proxy settings in your script accordingly.

* Run the script by providing the appropriate values for the command-line arguments.

  python check-s3-buckets.py -f s3_objects.txt -r us-west-2 -b my-bucket -p http://proxy_ip:proxy_port

* You can replace us-west-2 with the appropriate region code for your S3 bucket, and my-bucket with the actual name of your S3 bucket. Also replace the proxy_ip and proxy_port with the actual values of your proxy server.

* The script will check each key name in the s3_objects.txt file, send the request for each object through the specified proxy and print the url of the object if it exists and print the error if the object doesn't exist.

# Finding secrets in S3 objects

You can use find-secrets.py to search for secrets inside the AWS S3 Objects.

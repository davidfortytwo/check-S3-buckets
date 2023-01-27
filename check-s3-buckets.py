import argparse
import boto3
from botocore.exceptions import NoCredentialsError
import os
import requests

def check_bucket_objects(bucket_name, region_code, key_name):
    try:
        s3 = boto3.client('s3', region_name=region_code)
        s3.head_object(Bucket=bucket_name, Key=key_name)
        url = f'https://{bucket_name}.s3.{region_code}.amazonaws.com/{key_name}'
        response = requests.get(url, verify=True)
        if response.status_code == 200:
            print(f'{key_name} exists in bucket {bucket_name} and the url is {url}')
        else:
            print(f'Error in status code : {response.status_code}')
    except s3.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            print(f'{key_name} does not exist in bucket {bucket_name}')
        else:
            raise e
    except NoCredentialsError as e:
        print("Credentials not available")
        raise e
    except Exception as e:
        print(f'Error in accessing the object: {e}')
        raise e

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check S3 bucket objects')
    parser.add_argument('-f', '--file', dest='file_name', required=True, help='File with key names list')
    parser.add_argument('-r', '--region', dest='region_code', required=True, help='Region code')
    parser.add_argument('-b', '--bucket', dest='bucket_name', required=True, help='Bucket name')
    parser.add_argument('-p', '--proxy', dest='proxy', required=False, help='Proxy server')
    args = parser.parse_args()
    with open(args.file_name, 'r') as f:
        key_names = f.read().splitlines()
    for key_name in key_names:
        check_bucket_objects(args.bucket_name, args.region_code, key_name, args.proxy)

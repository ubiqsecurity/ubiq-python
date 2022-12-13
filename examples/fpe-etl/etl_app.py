# This example shows how to read a CSV file from Amazon S3,
# encrypt either the whole file, or specific fields, and upload
# the finalized file back to S3.

from distutils.command.config import config
import boto3
import csv
import io
import random
import ubiq_security as ubiq
import ubiq_security.fpe as ubiqfpe

# Prerequisite: define bucket name and file name. An example of RAW_DATA.csv exists in the etl_example folder.
bucket_name="test-bucket"
file_name="RAW_DATA.csv"
encrypt_full=True
encrypt_fields=True

# Initialized with credentials from either ENV variables or ~/.ubiq/credentials
credentials = ubiq.configCredentials()

s3 = boto3.client('s3')

# Retrieve the file from S3
response = s3.get_object(Bucket=bucket_name, Key=file_name)
full_doc = response['Body'].read().decode('utf-8')

# Encrypt the whole document at once
if encrypt_full:
    print('Encrypting full document')
    full_doc_encrypted = ubiq.encrypt(credentials, full_doc.encode())
    print('Uploading full encrypted doc to S3')
    s3.upload_fileobj(io.BytesIO(full_doc_encrypted), bucket_name, 'FULL_ENCRYPT.csv')
    print('Upload complete')

# Encrypt specific data
if encrypt_fields:
    print('Encrypting line by line')
    lines = full_doc.splitlines(True)
    transformed_rows = []
    headers = lines[0].split(',')

    reader = csv.DictReader(lines)
    for row in reader: 
        print(row['id'], row['username'])

        # TODO: Format Preserving Encryption, for now regular encryption.
        row['full_name_sensitive'] = ubiqfpe.Encrypt(credentials, 'FULL_NAME_ETL', row['full_name_sensitive'])
        row['email_sensitive'] = ubiqfpe.Encrypt(credentials, 'EMAIL_ETL', row['email_sensitive'], None)
        row['phone_number_sensitive'] = ubiqfpe.Encrypt(credentials, 'PHONE_ETL', row['phone_number_sensitive'])
        row['ssn_sensitive'] = ubiqfpe.Encrypt(credentials, 'SSN_ETL', row['ssn_sensitive'])
        
        transformed_rows.append(list(row.values()))

    print('Rows transformed, encoding to upload.')
    # Builing output object for S3
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(headers)
    writer.writerows(transformed_rows)
    byte_buff = io.BytesIO(csv_buffer.getvalue().encode())
    print('Uploading to S3')
    s3.upload_fileobj(byte_buff, bucket_name, 'TRANSFORMED_DATA.csv')
    print('Upload complete')

print('Done')
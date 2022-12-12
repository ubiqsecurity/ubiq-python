# Format Preserving Encrpytion ETL Example

This example shows how to encrypt specific fields in a CSV and store them on a cloud storage provider.

## Setup
### Dependencies
This script requires the `ubiq-security` and `boto` packages to be installed.
```shell
pip install ubiq-security boto
```
A pipfile has been provided, if you choose to use Pyenv to manage your dependencies.
This example uses Amazon's S3 as our cloud provider, and boto is the SDK.
### Storage
Provided is `RAW_DATA.csv`. This is around 1000 lines of randomly generated user data. This will need to be stored in your S3 bucket, and the script updated on Line 14 to reflect the name of your bucket. 
```python
bucket_name="test-bucket"
file_name="RAW_DATA.csv"
```
### FPE Definitions
On your account you should create 4 Datasets in the same Dataset Group, accessible by your API Key. (If you choose different names, update your local script accordingly, Line 48-51)
1. FULL_NAME_ETL
   - Input: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'-.`
   - Output: ``&-;@\^|!"#$%()*+./:<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_{}0123456789~'`abcdefghijklmnopqrstuvwxyz``
   - Passthrough: ` ` (A single space character)
   - Input Length: Min 9 Max 200
   - Max Rotations 93
2. EMAIL_ETL
   - Input: `0123456789abcdefghijklmnopqrstuvwxyz+-=`
   - Output: ``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/=[]{}()+``
   - Passthrough: `@.`
   - Input Length: Min 6 Max 100
   - Max Rotations 35
3. PHONE_ETL
   - Input: `0123456789`
   - Output: ``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ``
   - Passthrough: `-`
   - Input Length: Min 6 Max 20
   - Max Rotations 62
4. SSN_ETL
   - Input: `0123456789`
   - Output: ``0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ``
   - Passthrough: `-` 
   - Input Length: Min 9 Max 11
   - Max Rotations 62

Each of these definitions is crafted so the end result looks similar to the output. An email like an email, phone number like a phone number, etc. Max rotations is provided so you know if you have everything correct.

## Running
To run:
```shell
python etl_app.py
```
or with PipEnv
```shell
pipenv run python etl_app.py
```

The script should read from your bucket, encrypt the specific fields, and then place a new file `TRANSFORMED_DATA.csv` in your bucket.

## Viewing the Data in Amazon Athena

The following command can be used to create a table using the transformed data. This is handy for verifying the transformed data.
```sql
CREATE DATABASE POC_DATABASE;
DROP TABLE POC_TABLE;

CREATE EXTERNAL TABLE IF NOT EXISTS `POC_DATABASE`.`POC_TABLE` (
  `id` int,
  `username` string,
  `user_preferences` string,
  `contact_number` string,
  `user_bio` string,
  `email_sensitive` string,
  `full_name_sensitive` string,
  `phone_number_sensitive` string,
  `ssn_sensitive` string
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe'
WITH SERDEPROPERTIES (
  'serialization.format' = ',',
  'field.delim' = ','
)
LOCATION 's3://test-bucket/athena/'
TBLPROPERTIES (
    'has_encrypted_data' = 'false',
    'skip.header.line.count' = '1'
);

SELECT * FROM POC_TABLE;
```
You will see that only the fields we specified have been changed, while the rest of the content is still clearly visible.
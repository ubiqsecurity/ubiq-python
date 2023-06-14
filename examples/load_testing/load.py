# Subject to the foregoing terms and conditions, Ubiq hereby grants to You, at
# no cost, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable
# (except as stated herein) license to the Software, including all right to
# reproduce, prepare derivative works of, sublicense, and distribute the same.
# In the event You institute any litigation, or otherwise make any claim,
# against Ubiq for any reason (including a cross-claim or counterclaim in
# a lawsuit), or violate the terms of this license in any way, this license
# shall terminate automatically, without notice or liability, as of the date
# such litigation is filed or such violation occurs.  This license does not
# grant permission to use Ubiq’s trade names, trademarks, service marks, or
# product names in any way without Ubiq’s express prior written consent.
# THE SOFTWARE IS PROVIDED ON AN “AS IS” BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT
# LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
# MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE. YOU ASSUME ANY
# AND ALL RISKS ASSOCIATED WITH YOUR EXERCISE OF ANY RIGHTS GRANTED HEREUNDER.
# UBIQ SHALL HAVE LIABILITY TO YOU OR TO ANY THIRD PARTIES WITH RESPECT TO
# THIS LICENSE FOR (i) SPECIAL, CONSEQUENTIAL, EXEMPLARY, INCIDENTAL, OR
# PUNITIVE DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOST PROFITS, LOST
# REVENUES, LOST BUSINESS OPPORTUNITIES, LOSS OF USE OR EQUIPMENT DOWNTIME,
# AND LOSS OF OR CORRUPTION TO DATA), REGARDLESS OF THE LEGAL THEORY UNDER
# WHICH THEY ARE SOUGHT (INCLUDING, BUT NOT LIMITED TO ACTIONS FOR BREACH OF
# CONTRACT, NEGLIGENCE, STRICT LIABILITY, RESCISSION AND BREACH OF WARRANTY),
# EVEN IF UBIQ HAD BEEN ADVISED OF, OR SHOULD HAVE FORESEEN, THE POSSIBILITY
# OF SUCH DAMAGES, OR (ii) DIRECT DAMAGES EXCEEDING ONE DOLLAR.  IN NO EVENT
# SHALL UBIQ BE LIABLE FOR COSTS OF PROCUREMENT OF SUBSTITUTE PRODUCTS.
# YOU ACKNOWLEDGE AND AGREE THAT ALL LIMITATIONS AND DISCLAIMERS APPLICABLE
# TO THIS LICENSE ARE ESSENTIAL ELEMENTS OF THIS LICENSE AND THAT THESE
# REFLECT AN EQUITABLE ALLOCATION OF RISK BETWEEN THE PARTIES AND THAT IN
# THEIR ABSENCE THE TERMS OF THIS LICENSE WOULD BE SUBSTANTIALLY DIFFERENT.

'''
  Sample application for testing the runtime of encrypting and decrypting
  using various dataset definitions.

  Expects the API key has access to structured dataset definitions:
  FULL_NAME
    input abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'-.
    output abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
    passthrough ' ' (single space)
    min 5 max 255
  EMAIL
    input abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-
    output abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789! "#$%&'()*+,-/:;<=>?[\]^_`{|}~
    passthrough @.
    min 6 max 255
  PHONE
    input 0123456789
    output !"#$%&'()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
    passthrough -
    min 7 max 255
  SSN 
    input 0123456789 
    output 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 
    passthrough -
    min 11 max 255


@author:     Ubiq Security, Inc

@copyright:  2023- Ubiq Security, Inc. All rights reserved.

@contact:    support@ubiqsecurity.com
@deffield    updated: Updated
'''

import csv
import traceback
import ubiq_security as ubiq
import ubiq_security.fpe as ubiqfpe
import time
import sys
import os

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 1.0
__date__ = '2023-06-08'
__updated__ = '2023-06-08'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

DECIMAL_FORMAT = "{:.4f}"


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by Ubiq Security, Inc.
  Copyright 2021- Ubiq Security, Inc., All rights reserved.

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc)

    try:
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('-c', '--creds', dest="credentials", help="Set the file name with the API credentials (default: ~/.ubiq/credentials)", required=False)
        parser.add_argument('-P', '--profile', dest="profile", help="Identify the profile within the credentials file (default: default)", required=False, default='default')

        parser.add_argument('-e', '--encrypt', action="store_true", dest="encryption", help="Test encryption")
        parser.add_argument('-d', '--decrypt', action="store_true", dest="decryption" ,help="Test decryption")
        parser.add_argument('-v', '--verbose', action="store_true", dest="verbose" ,help="Verbose output")

        parser.add_argument('-ef', '--encryptfile', dest="encrypt_file", help="Filename of CSV with data to use for load testing")
        parser.add_argument('-df', '--decryptfile', dest="decrypt_file", help="Encrypted file to decrypt (Not passing will instead require encrypting to decrypt)")
        parser.add_argument('-i', '--iterations', dest="iterations", help="Times to run the whole data", default=20)

        args = parser.parse_args()

        creds = ubiq.configCredentials(args.credentials, args.profile)
        enc = args.encryption
        dec = args.decryption
        verbose = args.verbose
        iter = int(args.iterations)
        encrypt_file = args.encrypt_file
        decrypt_file = args.decrypt_file

        encfile = None
        decfile = None

        if enc and not encrypt_file:
            raise Exception('Encryption requires data to encrypt. Please provide a filename with -ef')
        if dec and not (enc or decrypt_file):
            raise Exception('Decryption test requires either encryption or encrypted file to be provided.')
        
        if encrypt_file:
            try:
                encfile = open(encrypt_file, 'r')
            except Exception as e:
                raise Exception(f'Unable to open file {encrypt_file} for reading. Check path or access rights.')
        
        if decrypt_file:
            try:
                decfile = open(decrypt_file, 'r')
            except Exception as e:
                raise Exception(f'Unable to open file {decrypt_file} for reading. Check path or access rights.')
        

        return True, iter, enc, encfile, dec, decfile, creds, verbose
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return False
    except Exception as e:
        if DEBUG or TESTRUN:
            raise e
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": {0}\n".format(e))
        sys.stderr.write(indent + "  For help use --help\n")
        return False

def run_test(iterations, encrypt, encfile, decrypt, decfile, credentials, verbose):
    
    transformed_rows = []

    total_enc = 0
    total_dec = 0

    # Encrypt specific data
    if encrypt:
        if verbose:
            print(f'Encrypting {encfile.name}')
        first_pass=True
        full_doc = encfile.read()
        doc_rows = []
        lines = full_doc.splitlines(True)
        reader = csv.DictReader(lines)
        for row in reader: 
            doc_rows.append(row)


        start_enc = time.time()
        for i in range(iterations):
            for row in doc_rows:   
                transformed_row = {}

                # TODO: Format Preserving Encryption, for now regular encryption.
                transformed_row['full_name_sensitive'] = ubiqfpe.Encrypt(credentials, 'FULL_NAME', row['full_name_sensitive'])
                transformed_row['email_sensitive'] = ubiqfpe.Encrypt(credentials, 'EMAIL', row['email_sensitive'], None)
                transformed_row['phone_number_sensitive'] = ubiqfpe.Encrypt(credentials, 'PHONE', row['phone_number_sensitive'])
                transformed_row['ssn_sensitive'] = ubiqfpe.Encrypt(credentials, 'SSN', row['ssn_sensitive'])
                transformed_row['dependent_sensitive'] = ubiqfpe.Encrypt(credentials, 'FULL_NAME', row['full_name_sensitive'])
                transformed_row['og_name'] = row['full_name_sensitive']

                total_enc += 5
                
                if first_pass:
                    transformed_rows.append(transformed_row)
            first_pass = False

            if verbose:
                print('encrypted ' + str(total_enc) + ' times')
        end_enc = time.time()
        print('')
        format_enc_time = DECIMAL_FORMAT.format(end_enc - start_enc)
        format_avg_enc_time = DECIMAL_FORMAT.format((end_enc - start_enc)/total_enc * 1000)
        print(f"took {format_enc_time}s to encrypt {str(total_enc)} times ({format_avg_enc_time}ms avg)\n")

    if decrypt:
        if decfile:
            if verbose:
                print(f'Decrypting {decfile.name}')
            dec_doc = decfile.read()
            transformed_rows = []
            lines = dec_doc.splitlines(True)
            reader = csv.DictReader(lines)
            for row in reader: 
                transformed_rows.append(row)
        else:
            if verbose:
                print('Decrypting using previously encrypted data')

        start_dec = time.time()
        for i in range(iterations):
            for row in transformed_rows:
                decrypted_row = {}

                decrypted_row['full_name_sensitive'] = ubiqfpe.Decrypt(credentials, 'FULL_NAME', row['full_name_sensitive'])
                decrypted_row['email_sensitive'] = ubiqfpe.Decrypt(credentials, 'EMAIL', row['email_sensitive'], None)
                decrypted_row['phone_number_sensitive'] = ubiqfpe.Decrypt(credentials, 'PHONE', row['phone_number_sensitive'])
                decrypted_row['ssn_sensitive'] = ubiqfpe.Decrypt(credentials, 'SSN', row['ssn_sensitive'])
                decrypted_row['dependent_sensitive'] = ubiqfpe.Decrypt(credentials, 'FULL_NAME', row['full_name_sensitive'])

                total_dec += 5
            if verbose:
                print('decrypted ' + str(total_dec) + ' times')
        end_dec = time.time()
        print('')
        format_dec_time = DECIMAL_FORMAT.format(end_dec - start_dec)
        format_avg_dec_time = DECIMAL_FORMAT.format((end_dec - start_dec)/total_dec * 1000)
        print(f"took {format_dec_time}s to decrypt {str(total_dec)} times ({format_avg_dec_time}ms avg)\n")
        


if __name__ == "__main__":
    try:
        valid_args, iterations, encrypt, encfile, decrypt, decfile, creds, verbose = parse_args()
        run_test(iterations, encrypt, encfile, decrypt, decfile, creds, verbose)
    except Exception as e:
        valid_args = False
        traceback.print_exc(e)
    sys.exit(valid_args == True)
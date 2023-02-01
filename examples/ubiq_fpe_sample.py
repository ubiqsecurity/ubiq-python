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
  Sample application to provide examples of using the Ubiq Platform Python Client Library
  for Format Preserving encryption

  Sample application for using the Ubiq Platform to encrypt and decrypt data using
  field format specifications.

@author:     Ubiq Security, Inc

@copyright:  2023- Ubiq Security, Inc. All rights reserved.

@contact:    support@ubiqsecurity.com
@deffield    updated: Updated
'''

import sys
import os
import configparser

# Path to the encrypt / decrypt libraries
import  ubiq_security as ubiq
import ubiq_security.fpe as ubiq_fpe

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 1.0
__date__ = '2023-01-26'
__updated__ = '2023-01-26'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def parse_args(argv=None): # IGNORE:C0111
    '''Parse the command line options.'''

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
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('-e', '--encrypttext', dest="encryption", help="Set the field text value to encrypt and will return the encrypted cipher text.")
        parser.add_argument('-d', '--decrypttext', dest="decryption" ,help="Set the cipher text value to decrypt and will return the decrypted text.")

        parser.add_argument('-c', '--creds', dest="credentials", help="Set the file name with the API credentials (default: ~/.ubiq/credentials)", required=False)
        parser.add_argument('-P', '--profile', dest="profile", help="Identify the profile within the credentials file (default: default)", required=False, default='default')

        parser.add_argument('-n', '--ffsname', dest="ffs_name", help="Set the ffs name, for example SSN.", required=True)
               
        # Process arguments
        args = parser.parse_args()

        encryption = args.encryption
        decryption = args.decryption
        ffs_name = args.ffs_name

        ''' 
        Make sure an encrypt / decrypt operation has been specified
        '''
        if (encryption != None and decryption != None) or (encryption == None and decryption == None):
            raise CLIError("Encryption or Decrytion have to be specified but not both")


        creds = ubiq.configCredentials(args.credentials, args.profile)

        return True, encryption, decryption, ffs_name, creds

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return False
    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": {0}\n".format(e))
        sys.stderr.write(indent + "  For help use --help\n")
        return False

def simple_encryption(creds, ffs_name, data):
    ''' Sample of the Ubiq Platform using the simple encryption API.'''
    try:
       ct = ubiq_fpe.Encrypt(creds, ffs_name, data)
       print("ENCRYPTED cipher= %s \n" %(ct))
    except Exception as err:
       print("Error performing encryption: ", repr(err))

def simple_decryption(creds, ffs_name, data):
    ''' Sample of the Ubiq Platform using the simple decryption API.'''
    try:
       pt = ubiq_fpe.Decrypt(creds, ffs_name, data)
       print("DECRYPTED plainText= %s \n" %(pt))
    except Exception as err:
       print("Error performing decryption: ", repr(err))

# Main For the application
if __name__ == "__main__":
    try:
        # Parse the args and return the necessary information.  An error during
        # parsing or testing the input / output files will result in valid_args
        # being false which will prevent commands from being executed.
        valid_args, encryption, decryption, ffs_name, creds = parse_args()
        # If the arguments were valid, then process the encrypt or decrypt
        if valid_args:
            if encryption:
                status = simple_encryption(creds, ffs_name, encryption)
            else:
                status = simple_decryption(creds, ffs_name, decryption)
    except Exception as inst:
        valid_args = False

    sys.exit(valid_args == True)

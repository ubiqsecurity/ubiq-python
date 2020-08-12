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

  Sample application for using the Ubiq Platform to encrypt and decrypt data using
  both the Simple and Piecewise APIs.

@author:     Ubiq Security, Inc

@copyright:  2020 Ubiq Security, Inc. All rights reserved.

@contact:    support@ubiqsecurity.com
@deffield    updated: Updated
'''

import sys
import os
import configparser

# Path to the encrypt / decrypt libraries
import  ubiq_security as ubiq

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 1.0
__date__ = '2020-07-26'
__updated__ = '2020-07-26'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

# Allow simple encryption / decryption for files less than 50 MiB
MAX_SIMPLE_SIZE = 1025 * 1024 * 50

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
  Copyright 2020 Ubiq Security, Inc., All rights reserved.

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc)

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('-e', '--encrypt', action="store_true", dest="encryption", help="Encrypt the contents of the input file and write the results to output file")
        parser.add_argument('-d', '--decrypt', action="store_true", dest="decryption" ,help="Decrypt the contents of the input file and write the results to output file")
        parser.add_argument('-s', '--simple', action="store_true", dest="simple", help="Use the simple encryption / decryption interfaces")
        parser.add_argument('-p', '--pieceswise', action="store_true", dest="piecewise", help="Use the piecewise encryption / decryption interfaces")

        parser.add_argument('-i', '--in', dest="infile", help="Set input file name", required=True)
        parser.add_argument('-o', '--out', dest="outfile", help="Set output file name", required=True)
        parser.add_argument('-c', '--creds', dest="credentials", help="Set the file name with the API credentials (default: ~/.ubiq/credentials)", required=False)
        parser.add_argument('-P', '--profile', dest="profile", help="Identify the profile within the credentials file (default: default)", required=False, default='default')
               
        # Process arguments
        args = parser.parse_args()

        encryption = args.encryption
        decryption = args.decryption
        simple = args.simple
        piecewise = args.piecewise
        

        ''' 
        Make sure an encrypt / decrypt operation has been specified
        Make sure either the simple or piecewise APIs have been specified
        '''
        if encryption == decryption:
            raise CLIError("Encryption or Decrytion have to be specified but not both")

        if simple == piecewise:
            raise CLIError("simple or piecewise API option need to be specified but not both")

        creds = ubiq.configCredentials(args.credentials, args.profile)

        '''
        Make sure the input file and output files can be opened for reading / writing
        '''

        try:
           infile = open(args.infile, "rb")
           if simple and os.stat(args.infile).st_size > MAX_SIMPLE_SIZE:
                print ("NOTE: This is only for demonstration purposes and is designed to work on memory")
                print ("      constrained devices.  Therefore, this sample application will switch to")
                print ("      the piecewise APIs for files larger than {0} bytes in order to reduce".format(MAX_SIMPLE_SIZE))
                print ("      excesive resource usages on resource constrained IoT devices")
                simple = False
                piecewise = True
               
        except Exception as e:
            raise CLIError("Unable to open input file '{0}' for reading.  Check path or access rights.".format(args.infile))

        try:               
           outfile = open(args.outfile, "wb")
        except Exception as e:
            close(infile)
            raise CLIError("Unable to open output file '{0}' for writing.  Check path or access rights.".format(args.outfile))

        return True, encryption, simple, infile, outfile, creds

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return False
    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return False

def simple_encryption(infile, outfile, creds):
    ''' Sample of the Ubiq Platform using the simple encryption API.'''
    data = infile.read()
    try:
       ct = ubiq.encrypt(creds,
                  data)
       outfile.write(ct)
    except Exception as err:
       print("Error performing encryption: ", repr(err))

def simple_decryption(infile, outfile, creds):
    ''' Sample of the Ubiq Platform using the simple decryption API.'''
    data = infile.read()
    try:
       pt = ubiq.decrypt(creds, data)
       outfile.write(pt)
    except Exception as err:
       print("Error performing decryption: ", repr(err))

def piecewise_encryption(infile, outfile, creds):
    '''
    Sample of the Ubiq Platform using the piecewise encryption API.
    Reads a block of data at time, encrypts it, and writes to the output file
    '''

    # Read 1 MiB of plaintext data at a time
    BLOCK_SIZE = 1024 * 1024

    enc = ubiq.encryption(creds, 1)

    try:
        # Write out the header information
        outfile.write(enc.begin())
    
        # Loop until the end of the input file is reached
        while True:
            data = infile.read(BLOCK_SIZE)
            outfile.write(enc.update(data))
            if (len(data) != BLOCK_SIZE):
                break

        # Make sure an additional encrypted data is retrieved and written
        outfile.write(enc.end())
        
    except Exception as err:
        # Need to make sure the enc.end is called to cleanup resources
        # can ignore errors at this point
        msg = repr(err)
        try:
           enc.end()
        except:
           pass
        print("Error performing encryption: ", msg)


def piecewise_decryption(infile, outfile, creds):
    '''
    Sample of the Ubiq Platform using the piecewise decryption API.
    Reads a block of data at time, decrypts it, and writes to the output file
    '''
    
    # Read 1 MiB of encrypted data at a time
    BLOCK_SIZE = 1024 * 1024

    dec = ubiq.decryption(creds)

    try:
        # Write out the header information

        # Start the decryption and write out any necessary data
        outfile.write(dec.begin())

        # Loop until the end of the input file is reached
        while True:
            data = infile.read(BLOCK_SIZE)
            outfile.write(dec.update(data))
            if (len(data) != BLOCK_SIZE):
                break

        # Make sure an additional plaintext data is retrieved and written
        outfile.write(dec.end())

    except Exception as err:
        # Need to make sure the enc.end is called to cleanup resources
        # can ignore errors at this point
        msg = repr(err)
        try:
           dec.end()
        except:
           pass
        print("Error performing decryption: ", msg )

# Main For the application
if __name__ == "__main__":

    # Parse the args and return the necessary information.  An error during
    # parsing or testing the input / output files will result in valid_args
    # being false which will prevent commands from being executed.        
    valid_args, encryption, simple, infile, outfile, creds = parse_args()
    
    # If the arguments were valid, then process the encrypt or decrypt and 
    # use either the simple or piecewise APIs
    if valid_args:
        if simple:
            if encryption:
                status = simple_encryption(infile, outfile, creds) 
            else:
                status = simple_decryption(infile, outfile, creds)
        else:
            if encryption:
                status = piecewise_encryption(infile, outfile, creds) 
            else:
                status = piecewise_decryption(infile, outfile, creds)
        infile.close()
        outfile.close()
        
    sys.exit(valid_args == True)

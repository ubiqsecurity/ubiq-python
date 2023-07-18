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
  Application for load testing the library using a provided dataset for consistent
  testing. Will also validate aginst provided expected timings.

@author:     Ubiq Security, Inc

@copyright:  2021- Ubiq Security, Inc. All rights reserved.

@contact:    support@ubiqsecurity.com
@deffield    updated: Updated
'''

import sys
import os
import time
import json

import traceback

# Path to the encrypt / decrypt libraries
import  ubiq_security as ubiq
import ubiq_security.fpe as ubiq_fpe

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter


__all__ = []
__version__ = 1.0
__date__ = '2023-06-22'
__updated__ = '2020-06-22'

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
    
class Timer:
    start_time = None
    end_time = None
    laps = []

    def __init__(self, scale_factor = 1000):
        self.scale_factor = scale_factor
        self.reset()    

    def start(self):
        self.start_time = time.time_ns()
        self.end_time = None
    
    def stop(self):
        if not self.start_time:
            raise Exception('Timer was not started.')
        
        self.end_time = time.time_ns()
        elapsed = (self.end_time - self.start_time) / self.scale_factor
        self.laps.append(elapsed)

        return elapsed
    
    def cancel(self):
        self.start_time = None
        self.end_time = None

    def reset(self):
        self.start_time = None
        self.end_time = None
        self.laps = []

    def total(self):
        return sum(self.laps)
    
    def count(self):
        return len(self.laps)
    
    def average_time(self):
        return self.total()/self.count()
    
    def min_time(self):
        return min(self.laps)
    
    def max_time(self):
        return max(self.laps)

def parse_args(argv=None):  # IGNORE:C0111
    '''Parse the command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (
        program_version, program_build_date)
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
        parser = ArgumentParser(
            description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument('-V', '--version', action='version',
                            version=program_version_message)
        
        parser.add_argument('-D', '--maxdecrypt', dest="max_decrypt",
                            help="Maximum allowed total decrypt time in microseconds.  Not including first call to server")
        parser.add_argument('-E', '--maxencrypt', dest="max_encrypt",
                            help="Maximum allowed total encrypt time in microseconds.  Not including first call to server")
        parser.add_argument('-d', '--avgdecrypt', dest="avg_decrypt",
                            help="Maximum allowed average decrypt time in microseconds.  Not including first call to server")
        parser.add_argument('-e', '--avgencrypt', dest="avg_encrypt",
                            help="Maximum allowed average encrypt time in microseconds.  Not including first call to server")

        parser.add_argument('-i', '--in', dest="infile",
                            help="Set input file name", required=True)
        parser.add_argument('-c', '--creds', dest="credentials",
                            help="Set the file name with the API credentials (default: ~/.ubiq/credentials)", required=False)
        parser.add_argument('-P', '--profile', dest="profile",
                            help="Identify the profile within the credentials file (default: default)", required=False, default='default')

        # Process arguments
        args = parser.parse_args()

        max_encrypt = args.max_encrypt
        max_decrypt = args.max_decrypt
        avg_encrypt = args.avg_encrypt
        avg_decrypt = args.avg_encrypt


        creds = ubiq.configCredentials(args.credentials, args.profile)

        '''
        Make sure the input file and output files can be opened for reading / writing
        '''

        try:
            infile = open(args.infile, "rb")
        except Exception as e:
            raise CLIError(
                "Unable to open input file '{0}' for reading.  Check path or access rights.".format(args.infile))

        return True, infile, max_encrypt, max_decrypt, avg_encrypt, avg_decrypt, creds

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return False
    except Exception as e:
        if DEBUG or TESTRUN:
            raise (e)
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": {0}\n".format(e))
        sys.stderr.write(indent + "  For help use --help\n")
        return False

def print_output(timer_dict):
    total = 0
    count = 0
    for i, (dataset_name, timer) in enumerate(timer_dict.items()):
        print(f'    Dataset: {dataset_name}, Count: {timer.count()} Average: {int(timer.average_time())}, Total {int(timer.total())}, Min: {int(timer.min_time())}, Max: {int(timer.max_time())}')
        count += timer.count()
        total += timer.total()
    average = (total/count)

    print(f'        Total: Average: {int(total/count)}, Total: {int(total)}')
    print()
    return total, average

def evaluate_threshold(threshold, reality, label):
    if not threshold:
        print (f'NOTE: No maximum allowed {label} threshold supplied')
        # didn't violate threshold
        return True
    
    if reality < int(threshold):
        print(f'PASSED: Maximum allowed {label} threshold of {threshold} microseconds')
        return True
    else:
        print(f'FAILED: Exceeded maximum allowed {label} threshold of {threshold} microseconds')
        return False
    

def load_test(infile, max_encrypt, max_decrypt, avg_encrypt, avg_decrypt, creds):
    enc_datasets = {}
    dec_datasets = {}
    data = json.load(infile)

    count = 0
    for i in data:
        dataset_name = i['dataset']

        # Prime the cache
        if(dataset_name not in enc_datasets):
            ubiq_fpe.Encrypt(creds, dataset_name, i['plaintext'])
            ubiq_fpe.Decrypt(creds, dataset_name, i['ciphertext'])
        
        enc_timer = enc_datasets.setdefault(dataset_name, Timer())
        dec_timer = dec_datasets.setdefault(dataset_name, Timer())

        enc_timer.start()
        ct = ubiq_fpe.Encrypt(creds, dataset_name, i['plaintext'])
        enc_timer.stop()

        if i['ciphertext'] != ct:
            raise Exception('Ciphertext did not match encrypted plaintext')
        
        dec_timer.start()
        pt = ubiq_fpe.Decrypt(creds, dataset_name, i['ciphertext'])
        dec_timer.stop()

        if i['plaintext'] != pt:
            raise Exception('Ciphertext did not match encrypted plaintext')

        count += 1


    print(f'Encrypt records count: {count}. Times in (microseconds)')
    enc_total, enc_avg = print_output(enc_datasets)
    print(f'Decrypt records count: {count}. Times in (microseconds)')
    dec_total, dec_avg = print_output(dec_datasets)

    res = []
    res.append(evaluate_threshold(avg_encrypt, enc_avg, 'average encrypt'))
    res.append(evaluate_threshold(avg_decrypt, dec_avg, 'average decrypt'))
    res.append(evaluate_threshold(max_encrypt, enc_total, 'total encrypt'))
    res.append(evaluate_threshold(max_encrypt, dec_total, 'total decrypt'))

    return all(res)


# Main For the application
if __name__ == "__main__":

    try:
        # Parse the args and return the necessary information.  An error during
        # parsing or testing the input / output files will result in valid_args
        # being false which will prevent commands from being executed.
        valid_args, infile, max_encrypt, max_decrypt, avg_encrypt, avg_decrypt, creds = parse_args()

        # If the arguments were valid, then process the encrypt or decrypt and
        # use either the simple or piecewise APIs
        if valid_args:
            result = load_test(infile, max_encrypt, max_decrypt, avg_encrypt, avg_decrypt, creds)
            infile.close()
            sys.exit(result)

    except Exception as inst:
        valid_args = False
        traceback.print_exc(inst)

    sys.exit(valid_args == True)
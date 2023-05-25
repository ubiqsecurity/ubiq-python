import unittest

from ubiq_security.credentials import configCredentials
from ubiq_security.fpe import Encrypt, Decrypt, EncryptForSearch

class FPEEncyptForSearchTest(unittest.TestCase):
    def getCredentials(self):
        creds = configCredentials()
        return creds
    
    def validateSearch(self, dataset_name, plain_text, tweak=None):
        creds = self.getCredentials()
        ct = Encrypt(creds, dataset_name, plain_text)
        ct_arr = EncryptForSearch(creds, dataset_name, plain_text, tweak)

        self.assertIn(ct, ct_arr, f"Unable to find matching value for {plain_text}")

        for ct in ct_arr:
            pt = Decrypt(creds, dataset_name, ct)
            self.assertEqual(plain_text, pt, f'Entry in search did not decrypt properly.')
    
    def test_encryptFPE_ALPHANUM_SSN(self):
        self.validateSearch("ALPHANUM_SSN", ";0123456-789ABCDEF|")

    def test_encryptFPE_BIRTH_DATE(self):
        self.validateSearch("BIRTH_DATE", ";01\\02-1960|")

    def test_encryptFPE_SSN(self):
        self.validateSearch("SSN", "-0-1-2-3-4-5-6-7-8-9-")

    def test_encryptFPE_UTF8_STRING_COMPLEX(self):
        self.validateSearch("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ")

    def test_encryptFPE_UTF8_STRING_COMPLEX_2(self):
        self.validateSearch("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ")
        

if __name__ == '__main__':
    unittest.main()

import unittest

from ubiq_security.credentials import credentials
from ubiq_security.structured import Encrypt, Decrypt

class StructuredEncyptTest(unittest.TestCase):
    def getCredentials(self):
        creds = credentials()
        return creds

    def roundTrip(self, dataset_name, plain_text, expected_cipher_text, tweak=None):
        creds = self.getCredentials()
        ct = Encrypt(creds, dataset_name, plain_text, tweak)
        pt = Decrypt(creds, dataset_name, ct, tweak)

        self.assertEqual(plain_text, pt)

        pt = Decrypt(creds, dataset_name, expected_cipher_text, tweak)
        self.assertEqual(plain_text, pt)

        # Encrypt for Search test goes here when implemented
        # ct_arr = EncryptForSearch(creds, dataset_name, plain_text, tweak)
        # find ect in ct_arr, decrypt ct, assert equals
    
    def cycleEncryption(self, dataset_name, plain_text, credentials):
        ct = Encrypt(credentials, dataset_name, plain_text)
        pt = Decrypt(credentials, dataset_name, ct)
        return plain_text == pt

    def test_encrypt_ALPHANUM_SSN(self):
        self.roundTrip("ALPHANUM_SSN", ";0123456-789ABCDEF|",
                       ";!!!E7`+-ai1ykOp8r|")

    def test_encrypt_BIRTH_DATE(self):
        self.roundTrip("BIRTH_DATE", ";01\\02-1960|", ";!!\\!!-oKzi|")

    def test_encrypt_SSN(self):
        self.roundTrip("SSN", "-0-1-2-3-4-5-6-7-8-9-", "-0-0-0-0-1-I-L-8-j-D-")

    def test_encrypt_UTF8_STRING_COMPLEX(self):
        self.roundTrip("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ",
                       "ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ")

    def test_encrypt_UTF8_STRING_COMPLEX_2(self):
        self.roundTrip("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ",
                       "にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa")

    def test_encrypt_TEST_CACHING(self):
        try:
            creds = self.getCredentials()

            pt_generic = ";0123456-789ABCDEF|"
            ct_generic = ""

            pt_alphanum = ";01\\02-1960|"
            ct_alphanum = ""

            ct_generic = Encrypt(creds, "ALPHANUM_SSN", pt_generic, None)
            ct_alphanum = Encrypt(creds, "BIRTH_DATE", pt_alphanum, None)

            ct_generic_2 = Encrypt(creds, "ALPHANUM_SSN", pt_generic, None)
            ct_alphanum_2 = Encrypt(creds, "BIRTH_DATE", pt_alphanum, None)

            pt_generic_2 = Decrypt(creds, "ALPHANUM_SSN", ct_generic, None)
            pt_alphanum_2 = Decrypt(creds, "BIRTH_DATE", ct_alphanum, None)

            self.assertEqual(ct_generic, ct_generic_2)
            self.assertEqual(ct_alphanum_2, ct_alphanum)

            self.assertEqual(pt_generic, pt_generic_2)
            self.assertEqual(pt_alphanum, pt_alphanum_2)

        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)

    # #def test_encryptSearch(self):
    # #   pass

    # @unittest.skip("Not implemented")
    # def test_encrypt_MultipleCachedKeys(self):
    #     try:
    #         creds = self.getCredentials()

    #         tweakFF1 = bytearray(b'\x39\x38\x37\x36\x35\x34\x33\x32\x31\x30')

    #         # We don't give access to the clearKeyCache (FlushDataset/FlushKey) methods in the Structured library atm.

    #         pass
    #     except Exception as e:
    #         print(f"****************** Exception: {e}")
    #         self.fail(e)

    # # test Dataset Speed skipped
    
    def test_encrypt_Invald_Dataset(self):
        creds = self.getCredentials()

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('ERROR_DATASET', 'ABCDEFGHI', creds)
        
        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'HTTPError')
 
    def test_encrypt_InvalidCredentials(self):
            creds = credentials('a', 'b', 'c', "https://api.ubiqsecurity.com")

            with self.assertRaises(Exception) as e:
                self.cycleEncryption('ERROR_DATASET', 'ABCDEFGHI', creds)

            the_exception = e.exception
            self.assertIn(type(the_exception).__name__, ['ConnectionError', 'HTTPError'])

    def test_encrypt_Invalid_PT_CT(self):
        creds = self.getCredentials()

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('SSN', '123456789$', creds)

        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'RuntimeError')
        self.assertEqual(str(the_exception), 'Invalid input string character(s)')
        
    def test_encrypt_Invalid_LEN_1(self):
        creds = self.getCredentials()

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('SSN', '1234', creds)

        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'RuntimeError')
        self.assertEqual(str(the_exception), 'Invalid input len (4) min: 6 max 255')

    ## Max Length is not enforced atm.
    # def test_encrypt_Invalid_LEN_2(self):
    #     creds = self.getCredentials()

    #     with self.assertRaises(Exception) as e:
    #         self.cycleEncryption('SSN', '12345678901234567890', creds)

    #     the_exception = e.exception
    #     self.assertEqual(type(the_exception).__name__, 'RuntimeError')
    #     self.assertEqual(str(the_exception), 'Input or tweak length error')

    def test_encrypt_Invalid_specific_creds_1(self):
        creds = self.getCredentials()
        creds = credentials(
            creds.access_key_id[0:1], 
            creds.secret_signing_key, 
            creds.secret_crypto_access_key, 
            creds.host
        )

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'HTTPError')
        self.assertEqual(str(the_exception), 'HTTP Error 400: Bad Request')

    ## Caching only looks at PAPI/Access_Key_ID so these don't fail like they should if the def is already in cache,
    # def test_encrypt_Invalid_specific_creds_2(self):
    #     creds = self.getCredentials()
    #     creds = credentials(
    #         creds.access_key_id, 
    #         creds.secret_signing_key[0:1], 
    #         creds.secret_crypto_access_key, 
    #         creds.host
    #     )

    #     with self.assertRaises(Exception) as e:
    #         self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

    #     the_exception = e.exception
    #     self.assertEqual(type(the_exception).__name__, 'RuntimeError')
    #     self.assertEqual(str(the_exception), 'Input or tweak length error')

    ## Caching only looks at PAPI/Access_Key_ID so these don't fail like they should if the def is already in cache,
    # def test_encrypt_Invalid_specific_creds_3(self):
    #     creds = self.getCredentials()
    #     creds = credentials(
    #         creds.access_key_id, 
    #         creds.secret_signing_key, 
    #         creds.secret_crypto_access_key[0:1], 
    #         creds.host
    #     )

    #     with self.assertRaises(Exception) as e:
    #         self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

    #     the_exception = e.exception
    #     self.assertEqual(type(the_exception).__name__, 'RuntimeError')
    #     self.assertEqual(str(the_exception), 'Input or tweak length error')

    def test_encrypt_Invalid_specific_creds_4(self):
        creds = self.getCredentials()
        creds = credentials(
            creds.access_key_id[0:1], 
            creds.secret_signing_key, 
            creds.secret_crypto_access_key, 
            "pi.ubiqsecurity.com"
        )

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'ConnectionError')

    def test_encrypt_Invalid_specific_creds_5(self):
        creds = self.getCredentials()
        creds = credentials(
            creds.access_key_id[0:1], 
            creds.secret_signing_key, 
            creds.secret_crypto_access_key, 
            "ps://api.ubiqsecurity.com"
        )

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

        the_exception = e.exception
        self.assertEqual(type(the_exception).__name__, 'ConnectionError')

    def test_encrypt_Invalid_specific_creds_6(self):
        creds = self.getCredentials()
        creds = credentials(
            creds.access_key_id[0:1], 
            creds.secret_signing_key, 
            creds.secret_crypto_access_key, 
            "https://google.com" 
        )

        with self.assertRaises(Exception) as e:
            self.cycleEncryption('ALPHANUM_SSN', '123456789', creds)

        self.assertIsNotNone(e.exception)

    def test_encrypt_Invalid_keynum(self):
        creds = self.getCredentials()

        cipher = Encrypt(creds, "SSN", "0123456789", None)
        new_cipher = "}" + cipher[1:]
        
        with self.assertRaises(Exception) as e:
            decrypted = Decrypt(creds, "SSN", new_cipher, None)

        self.assertIsNotNone(e.exception)
    
    def test_encrypt_Error_handling_invalid_dataset(self):
        creds = self.getCredentials()

        with self.assertRaises(Exception) as e:
            self.cycleEncryption( "ERROR_MSG", " 01121231231231231& 1 &2311200 ", creds)

        self.assertIsNotNone(e.exception)
        self.assertEqual(type(e.exception).__name__, 'HTTPError')
        self.assertEqual(str(e.exception), 'HTTP Error 401: Unauthorized')
        

if __name__ == '__main__':
    unittest.main()

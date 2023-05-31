import unittest

from ubiq_security.credentials import configCredentials
import ubiq_security as ubiq

class EncyptTest(unittest.TestCase):
    def getCredentials(self):
        creds = configCredentials()
        return creds
    
    def encrypt_decrypt(self,plain_text):
        pt_byte = bytearray(plain_text, "utf-8")
        creds = self.getCredentials()
        ct = ""
        rec = ""
        try:
            ct = ubiq.encrypt(creds, pt_byte)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)
        
        try:
            rec = ubiq.decrypt(creds, ct)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)

        self.assertEqual(pt_byte, rec)

        ct_broke = ct[:-1] + b'\x00'
        self.assertRaises(Exception, ubiq.decrypt, creds, ct_broke)
    
    def test_setup(self):
        creds = self.getCredentials()
        try:
            ubiq.decryption(creds)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)

    def test_encrypt(self):
        creds = self.getCredentials()
        try:
            result = ubiq.encrypt(creds, "ABC".encode())
            # self.assertEqual(result, expected_result)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)
    
    def test_simple(self):
        self.encrypt_decrypt("ABC")

    def test_aes_block_size(self):
        self.encrypt_decrypt("ABCDEFGHIJKLMNOP")
    
    def test_aes_block_size_2xm1(self):
        self.encrypt_decrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
    
    def test_aes_block_size_2x(self):
        self.encrypt_decrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
    
    def test_aes_block_size_2xp1(self):
        self.encrypt_decrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456")

if __name__ == '__main__':
    unittest.main()

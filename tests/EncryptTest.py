import unittest

from ubiq_security.credentials import configCredentials
import ubiq_security as ubiq

class EncyptTest(unittest.TestCase):
    def getCredentials(self):
        creds = configCredentials()
        return creds
    
    def test_setup(self):
        creds = self.getCredentials()
        try:
            ubiq.encryption(creds, 1)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)

    def test_encrypt(self):
        creds = self.getCredentials()
        try:
            result = ubiq.encrypt(creds, bytearray("ABC", "utf-8"))
            # self.assertEqual(result, expected_result)
        except Exception as e:
            print(f"****************** Exception: {e}")
            self.fail(e)

    # Piecewise encrypt?

if __name__ == '__main__':
    unittest.main()

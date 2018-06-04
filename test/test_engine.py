
'''Test cases for the _engine.py module.'''

import filecmp
import os
import shutil
import tempfile

import unittest

from cryptkeeper import _engine

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Uncomment to show lower level logging statements.
# import logging
# logger = logging.getLogger()
# logger.setLevel(logging.DEBUG)
# shandler = logging.StreamHandler()
# shandler.setLevel(logging.INFO)  # Pick one.
# <!-- # shandler.setLevel(logging.DEBUG)  # Pick one. -->
# formatter = logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
#     )
# shandler.setFormatter(formatter)
# logger.addHandler(shandler)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class EngineTestBaseClass(unittest.TestCase):
    '''Common base class for Engine testing.'''

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def setUpClass(cls):
        '''Test case class common fixture setup.'''
        cls.tmpdir = tempfile.mkdtemp()

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def tearDownClass(cls):
        '''Test case class common fixture teardown.'''
        cls.clean_tmpdir()
        os.rmdir(cls.tmpdir)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def setUp(self):
        '''Test case common fixture setup.'''
        self.clean_tmpdir()

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def clean_tmpdir(cls):
        '''Remove all content from cls.tmpdir.'''
        for root, dirs, files in os.walk(cls.tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @staticmethod
    def get_random_key(key_size=256):
        """Generate a random key of the specified length."""
        return os.urandom(int(key_size/8))

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class TestEngine(EngineTestBaseClass):
    '''Test cases for Engine properties.'''

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def test_engine_encrypt(self):
        '''Test the _engine.encrypt method.'''

        key = self.get_random_key()

        plaintext_path = os.path.join(self.tmpdir, 'plaintext')
        orig_plaintext_path = plaintext_path + '.orig'

        with open(plaintext_path, 'w') as fptr:
            fptr.write('Slithy toves\n')

        # Create a backup so we can remove the original to ensure it's
        # recreated when we unencrypt with default naming.
        shutil.copy(plaintext_path, orig_plaintext_path)
        self.assertTrue(filecmp.cmp(plaintext_path, orig_plaintext_path))

        ciphertext_path = os.path.join(self.tmpdir, 'ciphertext')
        recovered_path = os.path.join(self.tmpdir, 'recoveredtext')

        # - - - - - - - - - - - - - - - -
        _engine.encrypt_file(key, plaintext_path, ciphertext_path)
        _engine.decrypt_file(key, ciphertext_path, recovered_path)
        self.assertTrue(filecmp.cmp(orig_plaintext_path, recovered_path))

        # - - - - - - - - - - - - - - - -
        _engine.encrypt_file(key, plaintext_path)
        # TODO: '.enc' and all other standard suffixes should be constants.

        self.assertTrue(
            os.path.basename(plaintext_path) + '.enc' in
            os.listdir(self.tmpdir)
            )

        # Make sure the decryption removes the '.enc' suffix.
        os.remove(plaintext_path)

        self.assertTrue(
            os.path.basename(plaintext_path) not in os.listdir(self.tmpdir)
            )

        _engine.decrypt_file(key, plaintext_path + '.enc')
        self.assertTrue(
            os.path.basename(plaintext_path) in
            os.listdir(self.tmpdir)
            )
        self.assertTrue(filecmp.cmp(plaintext_path, orig_plaintext_path))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define test suite.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# pylint: disable=invalid-name
load_case = unittest.TestLoader().loadTestsFromTestCase
all_suites = {
    # Lowercase these.
    'suite_TestEngine': load_case(
        TestEngine
        ),
    }

master_suite = unittest.TestSuite(all_suites.values())
# pylint: enable=invalid-name

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if __name__ == '__main__':
    unittest.main()
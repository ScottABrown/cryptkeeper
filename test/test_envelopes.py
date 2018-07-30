"""Test cases for the envelope.py module."""

import filecmp
import logging
import os
import shutil
import tempfile
import warnings

import unittest

# from cryptkeeper import _engine
from cryptkeeper import errors
from cryptkeeper import envelope

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

TESTING_KMS_MASTER_KEY_ID = (
    'cf04fbf4-8119-4441-953b-1e5115e859dd'
    )

TESTING_KMS_MASTER_KEY_ARN = (
    'arn:aws:kms:us-west-1:018405429474:key/'
    'cf04fbf4-8119-4441-953b-1e5115e859dd'
    )

# Suppress stdout messages in python 3.
root_logger = logging.getLogger()
fhandler = logging.FileHandler('/dev/null/')
root_logger.addHandler(fhandler)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class EnvelopesTestBaseClass(unittest.TestCase):
    """Common base class for Envelopes testing."""

    tmpdir = None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def setUpClass(cls):
        """Test case class common fixture setup."""
        cls.tmpdir = tempfile.mkdtemp()

        # Filter warnings.
        # See https://github.com/boto/boto3/issues/454.
        warnings.filterwarnings(
            "ignore", category=ResourceWarning,
            message="unclosed.*<ssl.SSLSocket.*>"
            )

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def tearDownClass(cls):
        """Test case class common fixture teardown."""
        cls.clean_tmpdir()
        os.rmdir(cls.tmpdir)

        cls.tmpdir = None  # Yeah, it's superfluous.

        # Unfilter warnings.
        # See https://github.com/boto/boto3/issues/454.
        warnings.resetwarnings()

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def setUp(self):
        """Test case common fixture setup."""

        self.clean_tmpdir()

        self.assertIn('AWS_PROFILE', list(os.environ.keys()))
        self.assertIn('AWS_DEFAULT_REGION', os.environ)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @classmethod
    def clean_tmpdir(cls):
        """Remove all content from cls.tmpdir."""
        if cls.tmpdir:
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
class TestKmsAgentModule(EnvelopesTestBaseClass):
    """Test cases for KmsAgent class functionality. """

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @unittest.skipIf(not hasattr(envelope, 'plain_name'), 'Not implemented')
    def test_kms_agent_filename_methods(self):
        """Test KmsAgent module filename manipulation methods. """

        # - - - - - - - - - - - - - - - -
        plain_name = 'plaintext'
        archive_name = '.'.join([plain_name, 'tgz'])
        envelope_name = '.'.join([plain_name, 'kms-envelope'])
        envelope_archive_name = '.'.join([envelope_name, 'kms-tgz'])

        self.assertEqual(envelope.plain_name(plain_name), plain_name)
        self.assertEqual(envelope.archive_name(plain_name), archive_name)
        self.assertEqual(envelope.envelope_name(plain_name), envelope_name)
        self.assertEqual(envelope.envelope_archive_name(plain_name), envelope_archive_name)

        self.assertEqual(envelope.plain_name(archive_name), plain_name)
        self.assertEqual(envelope.archive_name(archive_name), archive_name)
        self.assertEqual(envelope.envelope_name(archive_name), envelope_name)
        self.assertEqual(envelope.envelope_archive_name(archive_name), envelope_archive_name)

        self.assertEqual(envelope.plain_name(envelope_name), plain_name)
        self.assertEqual(envelope.archive_name(envelope_name), archive_name)
        self.assertEqual(envelope.envelope_name(envelope_name), envelope_name)
        self.assertEqual(envelope.envelope_archive_name(envelope_name), envelope_archive_name)

        self.assertEqual(envelope.plain_name(envelope_archive_name), plain_name)
        self.assertEqual(envelope.archive_name(envelope_archive_name), archive_name)
        self.assertEqual(envelope.envelope_name(envelope_archive_name), envelope_name)
        self.assertEqual(envelope.envelope_archive_name(envelope_archive_name), envelope_archive_name)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class TestKmsAgent(EnvelopesTestBaseClass):
    """Test cases for KmsAgent class functionality. """

    # TODO: Check for environment variables with AWS profile, credentials, etc.

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def test_kms_agent_initialization_errors(self):
        """Test KmsAgent initialization errors. """

        # - - - - - - - - - - - - - - - -
        with self.assertRaises(errors.KmsHelperInitializationError):
            envelope.KmsAgent()


    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def test_kms_agent_initialize(self):
        """Test KmsAgent initialization. """

        # - - - - - - - - - - - - - - - -
        mki_agent = envelope.KmsAgent(
            master_key_id=TESTING_KMS_MASTER_KEY_ID
            )

        self.assertIsNotNone(mki_agent.master_key_alias)
        self.assertEqual(mki_agent.master_key_alias, TESTING_KMS_MASTER_KEY_ID)
        self.assertEqual(mki_agent.master_key_id, TESTING_KMS_MASTER_KEY_ARN)

        self.assertIsNotNone(mki_agent.master_key_id)
        self.assertIsNotNone(mki_agent.data_key)
        self.assertIsNotNone(mki_agent.ciphertext_blob)

        # - - - - - - - - - - - - - - - -
        mki_agent = envelope.KmsAgent(
            master_key_id=TESTING_KMS_MASTER_KEY_ARN
            )

        self.assertIsNone(mki_agent.master_key_alias)
        self.assertEqual(mki_agent.master_key_id, TESTING_KMS_MASTER_KEY_ARN)

        self.assertIsNotNone(mki_agent.master_key_id)
        self.assertIsNotNone(mki_agent.data_key)
        self.assertIsNotNone(mki_agent.ciphertext_blob)

        # - - - - - - - - - - - - - - - -
        data_key = mki_agent.data_key

        dk_agent = envelope.KmsAgent(
            master_key_id=TESTING_KMS_MASTER_KEY_ARN,
            data_key=data_key
            )

        self.assertIsNone(mki_agent.master_key_alias)
        self.assertEqual(mki_agent.master_key_id, TESTING_KMS_MASTER_KEY_ARN)

        self.assertIsNotNone(mki_agent.master_key_id)
        self.assertIsNotNone(mki_agent.data_key)
        self.assertIsNotNone(mki_agent.ciphertext_blob)

        # - - - - - - - - - - - - - - - -
        blob = dk_agent.ciphertext_blob

        cb_agent = envelope.KmsAgent(
            ciphertext_blob=blob
            )

        self.assertIsNone(mki_agent.master_key_alias)

        self.assertIsNotNone(mki_agent.master_key_id)
        self.assertIsNotNone(mki_agent.data_key)
        self.assertIsNotNone(mki_agent.ciphertext_blob)

        self.assertEqual(cb_agent.master_key_id, TESTING_KMS_MASTER_KEY_ARN)
        self.assertEqual(cb_agent.data_key, data_key)


    # - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def test_kms_agent_envelope(self):
        """Test KmsAgent envelope creation. """

        plaintext_path = os.path.join(self.tmpdir, 'plaintext')
        orig_plaintext_path = plaintext_path + '.orig'

        with open(plaintext_path, 'w') as fptr:
            fptr.write('Slithy toves\n')

        # Create a backup so we can remove the original to ensure it's
        # recreated when we unencrypt with default naming.
        shutil.copy(plaintext_path, orig_plaintext_path)
        self.assertTrue(filecmp.cmp(plaintext_path, orig_plaintext_path))

        # - - - - - - - - - - - - - - - -
        agent = envelope.KmsAgent(
            master_key_id=TESTING_KMS_MASTER_KEY_ARN
            )

        expected_envelope_archive_path = os.path.join(
            self.tmpdir, plaintext_path + '.kms-envelope.tgz'
            )
        envelope_path = agent.create_envelope(plaintext_path, self.tmpdir)

        self.assertEqual(envelope_path, expected_envelope_archive_path)
        self.assertTrue(os.path.exists(envelope_path))

        # Remove the original plaintext path and see if it recreates.
        os.remove(plaintext_path)
        self.assertFalse(os.path.exists(plaintext_path))

        unpacked_path = agent.open_envelope(envelope_path, self.tmpdir)

        self.assertEqual(unpacked_path, plaintext_path)
        self.assertTrue(os.path.exists(plaintext_path))
        self.assertTrue(filecmp.cmp(plaintext_path, orig_plaintext_path))


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define test suite.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# pylint: disable=invalid-name
load_case = unittest.TestLoader().loadTestsFromTestCase
all_suites = {
    # Lowercase these.
    'suite_TestKmsAgent': load_case(
        TestKmsAgent
        ),
    }

master_suite = unittest.TestSuite(all_suites.values())
# pylint: enable=invalid-name

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if __name__ == '__main__':
    unittest.main()
"""envelope.py

Tools for working with Amazon KMS.
"""

import logging
import os
import tarfile
import tempfile

import boto3

from cryptkeeper import _engine
from cryptkeeper import errors

HTTP_OK = 200

_logger = logging.getLogger(__name__)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class KmsAgent(object):
    """Manage KMS Key interactions."""

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def __init__(
            self,
            master_key_id=None,
            data_key=None,
            ciphertext_blob=None,
            profile_name=None,  # TODO: deprecated. Expect environment.
            region_name=None,  # TODO: deprecated. Expect environment.
            ):
        """Initialize a KmsAgent instance.

        Arguments:

            master_key_id
                XXX

            data_key
                XXX

            ciphertext_blob
                XXX

            profile_name
                XXX  # TODO: deprecated. Expect environment.

            region_name
                XXX  # TODO: deprecated. Expect environment.


        """

        # At least one of the master_key_id, data_key and ciphertext_blob must
        # be defined. Ciphertext blob must be defined alone,
        # while master_key_id can be defined with or without data_key but
        # is required if data_key is defined.
        msg = None
        if list({master_key_id, data_key, ciphertext_blob}) == [None]:
            msg = (
                'At least one of master_key_id, data_key and ciphertext_blob'
                ' is required.'
                )
        if ciphertext_blob and list({master_key_id, data_key}) != [None]:
            msg = (
                'If ciphertext_blob is defined, master_key_id and data_key'
                ' must be undefined.'
                )
        if data_key and not master_key_id:
            msg = 'If data_key is defined, master_key_id must also be defined.'

        if msg:
            _logger.error(msg)
            raise errors.KmsHelperInitializationError(msg)

        # - - - - - - - - - - - - - - - - - - - - - - - -
        self._kms_client = None

        # This could also be an alias.
        self._master_key_id = master_key_id
        self._data_key = data_key
        self._ciphertext_blob = ciphertext_blob

        self._master_key_alias = None

        self.profile_name = profile_name  # TODO: deprecated.
        self.region_name = region_name  # TODO: deprecated. Expect environment.

        if self._ciphertext_blob:
            # - - - - - - - - - - - - - - - - - - - - - - - -
            # We have only a ciphertext blob. We pass it to AWS KMS to decrypt
            # it from which we obtain our master_key_id and data_key.
            # - - - - - - - - - - - - - - - - - - - - - - - -

            response = self.kms_client.decrypt(
                CiphertextBlob=ciphertext_blob
                )

            response_metadata = response['ResponseMetadata']
            status_code = response_metadata['HTTPStatusCode']
            if status_code != HTTP_OK:
                msg = "HTTP {} response to AWS KMS decrypt() call {}."
                _logger.error(msg, status_code, response_metadata['RequestId'])
                raise errors.KmsAwsConnectionError(msg.format(
                    status_code, response_metadata['RequestId']
                    ))

            self._master_key_id = response['KeyId']
            self._data_key = response['Plaintext']

        elif self._data_key:
            # - - - - - - - - - - - - - - - - - - - - - - - -
            # We already checked above that master_key_id is defined. We pass
            # data_key to AWS KMS to retrieve a ciphertext_blob.
            # - - - - - - - - - - - - - - - - - - - - - - - -

            # TODO: catch kms_client.exceptions.NotFoundException and try as
            # alias.
            response = self.kms_client.encrypt(
                KeyId=self.master_key_id,
                Plaintext=data_key
                )

            response_metadata = response['ResponseMetadata']
            status_code = response_metadata['HTTPStatusCode']
            if status_code != HTTP_OK:
                msg = "HTTP {} response to AWS KMS encrypt() call {}."
                _logger.error(msg, status_code, response_metadata['RequestId'])
                raise errors.KmsAwsConnectionError(msg.format(
                    status_code, response_metadata['RequestId']
                    ))

            if response['KeyId'] != self.master_key_id:
                # We had an alias to start with, swap things around.
                self._master_key_alias = self.master_key_id
                self._master_key_id = response['KeyId']

            self._ciphertext_blob = response['CiphertextBlob']

        else:
            # - - - - - - - - - - - - - - - - - - - - - - - -
            # We have only a master_key_id. We use it to obtain a data key
            # and corresponding ciphertext_blob from AWS.
            # - - - - - - - - - - - - - - - - - - - - - - - -
            response = self.kms_client.generate_data_key(
                KeyId=self.master_key_id,
                KeySpec='AES_256'
                )

            response_metadata = response['ResponseMetadata']
            status_code = response_metadata['HTTPStatusCode']

            if status_code != HTTP_OK:
                msg = "HTTP {} response to AWS KMS generate_data_key() call {}."
                _logger.error(msg, status_code, response_metadata['RequestId'])
                raise errors.KmsAwsConnectionError(msg.format(
                    status_code, response_metadata['RequestId']
                    ))

            if response['KeyId'] != self.master_key_id:
                # We had an alias to start with, swap things around.
                self._master_key_alias = self.master_key_id
                self._master_key_id = response['KeyId']

            self._ciphertext_blob = response['CiphertextBlob']
            self._data_key = response['Plaintext']

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def kms_client(self):
        """Return the kms_client"""
        if self._kms_client is None:
            # We pass any not-None parameters from the pair.
            # TODO: deprecated. Expect environment.
            kwargs = dict([
                (u, v)
                for u, v in [
                    ('profile_name', self.profile_name),
                    ('region_name', self.region_name)
                    ]
                if v is not None
                ])
            session = boto3.session.Session(**kwargs)
            self._kms_client = session.client('kms')

        return self._kms_client

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def master_key_id(self):
        """Return the read-only master_key_id property value."""
        return self._master_key_id

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def master_key_alias(self):
        """Return the read-only master_key_alias property value."""
        return self._master_key_alias

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def data_key(self):
        """Return the read-only data_key property value."""
        return self._data_key

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def ciphertext_blob(self):
        """Return the read-only ciphertext_blob property value."""
        return self._ciphertext_blob

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def create_envelope(self, plaintext_path, output_path=None):
        """Create an encryption envelope with the encryption of the source.

        Arguments:

            plaintext_target
                XXX

            output_path
                XXX

        The envelope will be a .tgz archive of a directory containing the
        KmsAgent's ciphertext blob and the encryption of an "internal" .tgz
        archive of the file or directory specified in the
        `plaintext_path` parameter.

        """

        if output_path is None:
            output_path = os.path.dirname(plaintext_path) or '.'

        # Create a temporary working directory to build the envelope.
        # Create source.key-envelope in the temporary directory.
        # Create a tar archive of source in the temporary directory.
        # Write the ciphertext blob into source.key-envelope.
        # Encrypt the tar archive into source.key-envelope.
        # Create a tar archive of source.key-envelope in output path.
        # Remove the temporary directory.

        input_basename = os.path.basename(plaintext_path)
        envelope_name = '.'.join([input_basename, 'kms-envelope'])
        tmp_input_tar_name = '.'.join([input_basename, 'tgz'])
        tmp_encrypted_tar_name = '.'.join([tmp_input_tar_name, 'encrypt'])

        # Create a temporary working directory to build the envelope.
        tmpdir = tempfile.mkdtemp()

        tmp_envelope_path = os.path.join(tmpdir, envelope_name)
        tmp_input_tar_path = os.path.join(tmpdir, tmp_input_tar_name)
        blob_path = os.path.join(tmp_envelope_path, 'ciphertext-blob')
        encrypted_tar_path = os.path.join(
            tmp_envelope_path,
            tmp_encrypted_tar_name
            )

        if os.path.isdir(output_path):
            output_tar_name = '.'.join([envelope_name, 'tgz'])
            output_tar_path = os.path.join(output_path, output_tar_name)
        else:
            output_tar_path = output_path

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Paths calculated, let's get to work.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Create source.key-envelope in the temporary directory.
        os.mkdir(tmp_envelope_path)

        # Create a tar archive of source in the temporary directory.
        with tarfile.open(tmp_input_tar_path, 'w:gz') as source_tar_archive:
            # Use basename as arcname to prevent the archive element from being
            # located under the full path in the original filesystem.
            source_tar_archive.add(
                plaintext_path,
                arcname=os.path.basename(plaintext_path)
                )

        # Write the ciphertext blob into source.key-envelope.
        with open(blob_path, 'wb') as fptr:
            fptr.write(self.ciphertext_blob)

        # Encrypt the tar archive into source.key-envelope.
        _engine.encrypt_file(self.data_key, tmp_input_tar_path,
                             encrypted_tar_path)

        # Create a tar archive of source.key-envelope in output path.
        with tarfile.open(output_tar_path, 'w:gz') as output_archive:
            output_archive.add(
                tmp_envelope_path,
                arcname=os.path.basename(tmp_envelope_path)
                )

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Remove the temporary directory.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(tmpdir)

        return output_tar_path

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def open_envelope(self, input_path, output_path):
        """Obtain the plaintext of the contents of envelope_path.

        Arguments:

            envelope_path
                XXX

            output_path
                XXX

        """

        if output_path is None:
            output_path = os.path.dirname(plaintext_path) or '.'

        # Create a temporary working directory to build the envelope.
        # Untar envelope_path into the temporary directory.
        # Create a KmsAgent instance with the ciphertext_blob.
        # Unencrypt the encrypted file into the temporary directory.
        # Untar the unencrypted file to the output path.
        # Remove the temporary directory.

        # Create a temporary working directory to build the envelope.
        tmpdir = tempfile.mkdtemp()

        # input_tar_name = os.path.basename(input_path)
        # input_tar_path = os.path.join(tmpdir, input_tar_name)

        # Untar envelope_path into the temporary directory.
        # tmp_envelope_name = '.'.join([input_tar_name, 'untarred'])
        # tmp_envelope_path = os.path.join(tmpdir, tmp_envelope_name)
        with tarfile.open(input_path, 'r:gz') as input_tar_archive:
            input_tar_archive.extractall(path=tmpdir)

        # TODO: Use filename manipulation methods.
        kms_envelope_path = os.path.join(tmpdir, os.listdir(tmpdir)[0])
        ciphertext_blob_path = os.path.join(
            kms_envelope_path, 'ciphertext-blob'
            )

        # Create a KmsAgent instance with the ciphertext_blob.
        with open(ciphertext_blob_path, 'rb') as fptr:
            ciphertext_blob = fptr.read()
        agent = KmsAgent(ciphertext_blob=ciphertext_blob)

        # Unencrypt the encrypted file into the temporary directory.
        encrypted_archive_list = [
            f for f in os.listdir(kms_envelope_path) if f.split('.')[-1] == 'encrypt'
            ]
        # TODO: Ugh, no error checking!
        encrypted_archive_filename = encrypted_archive_list[0]
        decrypted_archive_filename = os.path.splitext(
            encrypted_archive_filename
            )[0]
        decrypted_archive_path = os.path.join(
            tmpdir, decrypted_archive_filename
            )
        _engine.decrypt_file(
            agent.data_key,
            os.path.join(kms_envelope_path, encrypted_archive_filename),
            out_filename=decrypted_archive_path
            )

        # Untar the unencrypted file to the output path.
        # TODO: This just assumes output_path is a directory.
        with tarfile.open(decrypted_archive_path, 'r:gz') as output_archive:
            output_archive.extractall(path=output_path)

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Remove the temporary directory.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(tmpdir)

        # TODO: This assumes so much...
        return os.path.join(
            output_path,
            os.path.splitext(os.path.basename(decrypted_archive_path))[0]
            )

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
class Enveloper(object):
    """Manage Envelope operations."""

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def __init__(self, kms_agent=None):
        """Initialize an Enveloper instance.

        Arguments:

            kms_agent
                XXX

        """

        self._active_agent = None

        if kms_agent:
            self._active_agent = kms_agent

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    @property
    def kms_agent(self):
        """Return the kms_agent property."""
        return self._active_agent

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def create_envelope(self, plaintext_path, output_path=None):
        """Create an encryption envelope with the encryption of the source.

        Arguments:

            plaintext_target
                XXX

            output_path
                XXX

        The envelope will be a .tgz archive of a directory containing the
        KmsAgent's ciphertext blob and the encryption of an "internal" .tgz
        archive of the file or directory specified in the
        `plaintext_path` parameter.

        """

        # TODO: Move to this code for envelopes, instead of in KmsAgent.

        # Create a temporary working directory to build the envelope.
        # Create source.key-envelope in the temporary directory.
        # Create a tar archive of source in the temporary directory.
        # Write the ciphertext blob into source.key-envelope.
        # Encrypt the tar archive into source.key-envelope.
        # Create a tar archive of source.key-envelope in output path.
        # Remove the temporary directory.

        input_basename = os.path.basename(plaintext_path)
        envelope_name = '.'.join([input_basename, 'kms-envelope'])
        tmp_input_tar_name = '.'.join([input_basename, 'tgz'])
        tmp_encrypted_tar_name = '.'.join([tmp_input_tar_name, 'encrypt'])

        # Create a temporary working directory to build the envelope.
        tmpdir = tempfile.mkdtemp()

        tmp_envelope_path = os.path.join(tmpdir, envelope_name)
        tmp_input_tar_path = os.path.join(tmpdir, tmp_input_tar_name)
        blob_path = os.path.join(tmp_envelope_path, 'ciphertext-blob')
        encrypted_tar_path = os.path.join(
            tmp_envelope_path,
            tmp_encrypted_tar_name
            )

        if os.path.isdir(output_path):
            output_tar_name = '.'.join([envelope_name, 'tgz'])
            output_tar_path = os.path.join(output_path, output_tar_name)
        else:
            output_tar_path = output_path

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Paths calculated, let's get to work.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Create source.key-envelope in the temporary directory.
        os.mkdir(tmp_envelope_path)

        # Create a tar archive of source in the temporary directory.
        with tarfile.open(tmp_input_tar_path, 'w:gz') as source_tar_archive:
            # Use basename as arcname to prevent the archive element from being
            # located under the full path in the original filesystem.
            source_tar_archive.add(
                plaintext_path,
                arcname=os.path.basename(plaintext_path)
                )

        # Write the ciphertext blob into source.key-envelope.
        with open(blob_path, 'wb') as fptr:
            fptr.write(self.ciphertext_blob)

        # Encrypt the tar archive into source.key-envelope.
        _engine.encrypt_file(self.data_key, tmp_input_tar_path,
                             encrypted_tar_path)

        # Create a tar archive of source.key-envelope in output path.
        with tarfile.open(output_tar_path, 'w:gz') as output_archive:
            output_archive.add(
                tmp_envelope_path,
                arcname=os.path.basename(tmp_envelope_path)
                )

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Remove the temporary directory.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(tmpdir)

        return output_tar_path

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    def open_envelope(self, input_path, output_path):
        """Obtain the plaintext of the contents of envelope_path.

        Arguments:

            envelope_path
                XXX

            output_path
                XXX

        """

        # TODO: Move to this code for envelopes, instead of in KmsAgent.

        # Create a temporary working directory to build the envelope.
        # Untar envelope_path into the temporary directory.
        # Create a KmsAgent instance with the ciphertext_blob.
        # Unencrypt the encrypted file into the temporary directory.
        # Untar the unencrypted file to the output path.
        # Remove the temporary directory.

        # Create a temporary working directory to build the envelope.
        tmpdir = tempfile.mkdtemp()

        # input_tar_name = os.path.basename(input_path)
        # input_tar_path = os.path.join(tmpdir, input_tar_name)

        # Untar envelope_path into the temporary directory.
        # tmp_envelope_name = '.'.join([input_tar_name, 'untarred'])
        # tmp_envelope_path = os.path.join(tmpdir, tmp_envelope_name)
        with tarfile.open(input_path, 'r:gz') as input_tar_archive:
            input_tar_archive.extractall(path=tmpdir)

        # TODO: Use filename manipulation methods.
        kms_envelope_path = os.path.join(tmpdir, os.listdir(tmpdir)[0])
        ciphertext_blob_path = os.path.join(
            kms_envelope_path, 'ciphertext-blob'
            )

        # Create a KmsAgent instance with the ciphertext_blob.
        with open(ciphertext_blob_path, 'rb') as fptr:
            ciphertext_blob = fptr.read()
        agent = KmsAgent(ciphertext_blob=ciphertext_blob)

        # Unencrypt the encrypted file into the temporary directory.
        encrypted_archive_list = [
            f for f in os.listdir(kms_envelope_path) if f.split('.')[-1] == 'encrypt'
            ]
        # TODO: Ugh, no error checking!
        encrypted_archive_filename = encrypted_archive_list[0]
        decrypted_archive_filename = os.path.splitext(
            encrypted_archive_filename
            )[0]
        decrypted_archive_path = os.path.join(
            tmpdir, decrypted_archive_filename
            )
        _engine.decrypt_file(
            agent.data_key,
            os.path.join(kms_envelope_path, encrypted_archive_filename),
            out_filename=decrypted_archive_path
            )

        # Untar the unencrypted file to the output path.
        # TODO: This just assumes output_path is a directory.
        with tarfile.open(decrypted_archive_path, 'r:gz') as output_archive:
            output_archive.extractall(path=output_path)

        # - - - - - - - - - - - - - - - - - - - - - - - -
        # Remove the temporary directory.
        # - - - - - - - - - - - - - - - - - - - - - - - -
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(tmpdir)

        # TODO: This assumes so much...
        return os.path.join(
            output_path,
            os.path.splitext(os.path.basename(decrypted_archive_path))[0]
            )
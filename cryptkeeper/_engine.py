"""_engine.py

Core encryption/decryption functionality.

See http://eli.thegreenplace.net/2010/06/25/
aes-encryption-of-files-in-python-with-pycrypto.

"""


import os
import struct

from Crypto.Cipher import AES
from Crypto import Random


_IV_SIZE = 16
_FILE_LENGTH_FIELD_SIZE = struct.calcsize('Q')
_CHUNK_MIN_SIZE = 1024
DEFAULT_ENCRYPT_CHUNKSIZE = 64 * _CHUNK_MIN_SIZE
DEFAULT_DECRYPT_CHUNKSIZE = 24 * _CHUNK_MIN_SIZE


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def encrypt_file(
        key, in_filename, out_filename=None, chunksize=DEFAULT_ENCRYPT_CHUNKSIZE
        ):
    """ Encrypts a file using AES (CBC mode) with the given key.

        key:
            The encryption key - a string that must be either 16, 24 or 32 bytes
            long. Longer keys are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function uses to read and
            encrypt the file. Larger chunk sizes can be faster for some files
            and machines. chunksize must be divisible by 16.

    """
    # TODO: Add a MAC in the padding?

    if not out_filename:
        out_filename = in_filename + '.enc'

    randomness = Random.new()

    # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(_IV_SIZE))
    iv = randomness.read(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as in_fptr:
        with open(out_filename, 'wb') as out_fptr:
            out_fptr.write(struct.pack('<Q', filesize))
            out_fptr.write(iv)

            final_block = False

            while True:
                chunk = in_fptr.read(chunksize)

                # if len(chunk) == 0:
                #     break
                # elif len(chunk) % 16 != 0:
                #     chunk += ' ' * (16 - len(chunk) % 16)

                # The original algorithm padded with a space character, but this
                # is not secure and also can corrupt data that happens to end in
                # spaces which are significant. We pad to a multiple of 16
                # with random bytes, then add a 16 byte block consisting of 8
                # random bytes and an 8 byte field containing the original file
                # length.

                chunk_length = len(chunk)
                filesize_record = struct.pack('<Q', filesize)
                filesize_record_length = len(filesize_record)

                if chunk_length == 0 or (chunk_length % 16) != 0:
                    final_block = True
                    chunk += randomness.read(16 - chunk_length % 16)

                    # # padding_length includes the final 8 byte field!
                    # padding_length = chunksize - chunk_length
                    # if padding_length < filesize_record_length:
                    #     # We pad this chunk with randomness and emit it, then
                    #     # set up to create a full padding chunk.
                    #     chunk += randomness.read(padding_length)
                    #     out_fptr.write(encryptor.encrypt(chunk))
                    #
                    #     chunk = ''
                    #     padding_length = chunksize
                    chunk += randomness.read(16 - filesize_record_length)
                    chunk += filesize_record
                    # print('Adding interim chunk size {}'.format(len(chunk)))

                enc = encryptor.encrypt(chunk)
                out_fptr.write(enc)
                if final_block:
                    break


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def decrypt_file(
        key,
        in_filename,
        out_filename=None,
        chunksize=DEFAULT_DECRYPT_CHUNKSIZE
        ):
    """ Decrypts a file using AES (CBC mode) with the given key.

    Parameters are similar to encrypt_file, with one difference: out_filename,
    if not supplied will be in_filename without its last extension (i.e. if
    in_filename is 'aaa.zip.enc' then out_filename will be 'aaa.zip')
    """

    if not out_filename:
        # TODO: This assumes we have a .enc suffix.
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as in_fptr:

        # Read the file size chunk first:
        file_length_field = in_fptr.read(_FILE_LENGTH_FIELD_SIZE)
        origsize = struct.unpack('<Q', file_length_field)[0]

        iv = in_fptr.read(_IV_SIZE)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as out_fptr:
            while True:
                chunk = in_fptr.read(chunksize)
                if len(chunk) == 0:
                    break
                out_fptr.write(decryptor.decrypt(chunk))

            out_fptr.truncate(origsize)
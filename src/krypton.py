import traceback  # Traceback library for printing formatted exception information.
import argparse   # Useful library for parsing command line arguments, and generating automatic help texts.
import hashlib    # Standard cryptographic hash function library, for.. hashing :)
import getpass    # Secure input library for passwords, hides input.
import random     # Standard library random functions, overridden by PyCryptoDome.
import time       # Time library, used for time.sleep()-ing the console.
import copy       # Copy library which can deepcopy a dict.
import json       # JSON Parsing and loading library.
import os         # OS Functions, also contains os.path module.

# Contains ASCII character classes, useful for password generation.
from string import ascii_letters, ascii_uppercase, ascii_lowercase
from string import punctuation as ascii_special
from string import digits as ascii_digits
from string import Formatter

# Union type, representing more than one possible value for parameter and variable type notation.
from typing import Union

# PyCryptoDome Cryptography Library
from Crypto.Cipher import AES
from Crypto import Random

# Argon2 Password Hashing For Key Derivation
import argon2

# Python Clipboard Library
import pyperclip

COMMAND_REFERENCE_TEXT: str = """
This is the command reference for Krypton, here you can find all of the relevant
commands for interacting with this password manager. This does not include the
command line arguments, to view those use the --help or -h argument when running Krypton.

Command Reference Legend
--------
N      = Denotes a numerical value, e,g, command [N] (command takes any number as an arugment)
|      = Denotes multiple available options (or)
,      = Denotes list of command aliases.
[]     = Denotes singular parameter, contents indicate type of value.
{...}  = Denotes a space-separated sequence of parameters of the same type.
--------

Navigating Krypton:
====================================================================================================
    [N]                    | Navigate to the page of that number. Any number goes.
----------------------------------------------------------------------------------------------------
    s, select   [N | N-N]  | Select the account with the given index, or account+entry if - is used.
                           | Example 1, selects account with index 12: "select 12"
                           | Example 2, selects account 12, entry 3: "select 12-3"
----------------------------------------------------------------------------------------------------
    cs, clearsel           | Deselects any accounts or entries selected using select.
----------------------------------------------------------------------------------------------------
    f, filter {terms...}   | Applies a display filter to the account list, accounts matching any of
                           | the provided search terms are whitelisted.
                           | Example: filter google twitter reddit
----------------------------------------------------------------------------------------------------
    cf, clearfilter        | Resets the display filter applied using the filter command.
----------------------------------------------------------------------------------------------------
    pr, rows [N]           | Modify the number of rows displayed per account page.
                           | Example: rows 10
----------------------------------------------------------------------------------------------------
    cp, copy               | Copies the entry selected using the select command to the clipboard.
====================================================================================================

Performing Edits In Krypton:
===================================================================================================
    a, add                 | Add a new entry to the selected account, values will be prompted for.
----------------------------------------------------------------------------------------------------
    del, delete            | Deletes the selected entry from the account it belogns to.
----------------------------------------------------------------------------------------------------
    mod, modify            | Modifies the selected entry, new value will be prompted for.
----------------------------------------------------------------------------------------------------
    aac, addacc            | Add a new account to the vault, details will be prompted for.
----------------------------------------------------------------------------------------------------
    dac, delacc            | Deletes the selected account from the vault.
----------------------------------------------------------------------------------------------------
    rand, random [N] {chars..}    | Inserts a random password into the selected account entry
                                  | Options: alpha, alphaupper, alphalower, numerical, special, extra
                                  | Example: random 32 alpha numerical special
====================================================================================================

Security Related Commands:
====================================================================================================
make-secure           | Turns on encryption for an insecure vault with decryption disabled.
----------------------------------------------------------------------------------------------------
make-insecure         | Turns off encryption for a vault with encryption enabled, making it insecure.
----------------------------------------------------------------------------------------------------
ivmask [N]            | Sets the length of the IV mask - the amount of random bytes appended/stripped
                      | from the encryption input/output data in order to guarantee a random output
                      | for the first round of XOR. Must be a minimum of 16 to be secure, but can
                      | be set to any size, though a high value will increase the file size.
----------------------------------------------------------------------------------------------------
dumpjson              | Dumps the vault stored in RAM into the terminal as raw unencrypted JSON.
                      | Useful in case you lose filesystem access for whatever reason, and must
                      | get your credentials out of RAM. One of the two options presented when
                      | an integrity check fails.
====================================================================================================

Saving, Viewing, Restoring Changes:
====================================================================================================
save                  | Saves the changes made to the vault back into the same file that was loaded.
                      | This will not allow you to store the vault to a new location, or use a different
                      | password than the one that was used to decrypt it in the first place.
----------------------------------------------------------------------------------------------------
write                 | Writes the vault to any given  location on the disk, but does not allow you
                      | to overwrite files, only new files can be created using this command. This
                      | also allows you to select a different password than the initial password.
----------------------------------------------------------------------------------------------------
restore, revert       | Reverts the state of the vault in RAM to the state it was at when the vault
                      | was loaded, or the last time that the save command was used.
----------------------------------------------------------------------------------------------------
diff                  | View an index of everything that was added, removed, or modified since the
                      | vault was loaded, or the last time that the save command was used.
====================================================================================================

Miscellaneous Commands
====================================================================================================
exit, quit            | Self-explanatory, exits the program.
----------------------------------------------------------------------------------------------------
help, ?, what         | Shows the command reference that you're viewing right now.
====================================================================================================
"""


class InvalidArgumentTypeError(TypeError):
    """Error where argument has an invalid type.
    """

    @staticmethod
    def auto(name: str, expected: type, got: type):
        message_format: str = "Argument '{0}' is of an invalid type, expected {1} got {2}"
        return InvalidArgumentTypeError(message_format.format(name, expected, got))

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class InvalidArgumentValueError(ValueError):
    """Error where an argument had an invalid value.
    """

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class IvMaskLengthError(ValueError):
    """Error describing the use of an invalid IV mask length.

    This is typically raised because an IV mask length was used which
    was greater than 0 and less than 16.
    """

    @staticmethod
    def auto(iv_mask_length: int):
        message_format: str = "Invalid IV mask length '{0}', must either be >= 16, or 0"
        return IvMaskLengthError(message_format.format(iv_mask_length))

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class InvalidDecryptionInputError(ValueError):
    """Error involving invalid decryption input data or invalid decryption parameters.

    An example might be attempting to decrypt a sequence of bytes that aren't encrypted,
    and therefore don't possess the correct size for an attempt at decryption.
    """

    @staticmethod
    def auto():
        message_format: str = "Bad input data was passed to the AES-CBC decryption function, and it threw an exception."
        return InvalidDecryptionInputError(message_format)

    def __str__(self) -> str:
        return self.message

    def __init__(self, message: str):
        self.message = message


class InvalidEncryptionInputError(ValueError):
    """Error involving invalid input data or invalid encryption parameters.

    An example might be the use of an invalid key size, or passing a value
    that isn't a sequence of bytes as an input to the encryption.
    """

    @staticmethod
    def auto():
        message_format: str = "Bad input data was passed to the AES-CBC encryption function, and it threw an exception."
        return InvalidEncryptionInputError(message_format)

    def __str__(self) -> str:
        return self.message

    def __init__(self, message: str):
        self.message = message


class PostDecryptionJsonLoadError(json.JSONDecodeError):
    """JSON Decode error that occurred after data has been decrypted.

    This generally indicates a decryption failure, as the output was
    non-parseable by JSON, but could also indicate invalid source data.
    """

    @staticmethod
    def auto():
        return PostDecryptionJsonLoadError("JSON Loading error encountered post-decryption, indicating that the "
                                           "decryption output was not JSON parsable.")

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class PostDecryptionUnicodeDecodeError(UnicodeDecodeError):
    """Unicode decode error that occurred after data has been decrypted.

    This generally indicates a decryption failure, as the output contained
    characters unmappable by UTF-8, but could also indicate invalid source data.
    """

    @staticmethod
    def auto():
        return PostDecryptionUnicodeDecodeError("Unicode decoding error encountered post-decryption, indicating that "
                                                "the decryption output cannot be interpreted as UTF-8 unicode.")

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class PreEncryptionJsonDumpError(TypeError):
    """JSON Dump error that occurred before encryption.

    This generally indicates an invalid vault_data dictionary.
    """

    @staticmethod
    def auto():
        return PreEncryptionJsonDumpError(
            "JSON Serialization error encountered pre-encryption, indicating that the target dictionary contained "
            "a value whose type cannot be represented in JSON.")

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class PreEncryptionUnicodeEncodeError(UnicodeEncodeError):
    """Unicode encode error that occurred before encryption.

    This generally indicates the presence of an unknown unmappable character
    as part of the encryption input.
    """

    @staticmethod
    def auto():
        return PreEncryptionUnicodeEncodeError(
            "Unicode encoding error encountered pre-encryption, indicating that the string destined for encryption "
            "contained a character that could not be mapped into the target encoding.")

    def __str__(self):
        return self.message

    def __init__(self, message: str):
        self.message = message


class ExceptionMessageResolver(object):
    """Contains all program exception messages that should be presented to the user.

    This point of this class is to generalize the storage of exception messages,
    and allow easy modification and addition of exception messages, as well as
    automatic exception message resolution based on exception source and type.
    """

    Master: dict = {
        "krypton_aes_cbc_encrypt": {
            IvMaskLengthError: "The provided IV mask length ({iv_mask_length}) is invalid, "
                               "it must either be 0 or greater than 16.",

            InvalidEncryptionInputError: "The data passed to krypton_aes_cbc_encrypt was invalid, most likely as a "
                                         "result of a padding error, please report this to the developer."
        },

        "krypton_aes_cbc_decrypt": {
            IvMaskLengthError: "The provided IV mask length ({iv_mask_length}) is invalid, "
                               "it must either be 0 or greater than 16.",

            InvalidDecryptionInputError: "An attempt was made to decrypt invalid data, most likely because the vault "
                                         "is insecure & unencrypted, or because the file is not a vault."
        },

        "write_vault": {
            # From write_vault
            InvalidArgumentValueError: "The most likely cause of this error is the password containing non-mappable "
                                       "Unicode characters.",

            InvalidArgumentTypeError: "The most likely cause of this error is a programmer oversight, "
                                      "please report this to the developer.",

            FileExistsError: "A vault at that location already exists, and overwrite is disabled for this operation.",

            PreEncryptionJsonDumpError: "Failed turn the empty vault_data template dictionary into JSON, this is most "
                                        "likely a programmer oversight, please report this to the developer.",

            PreEncryptionUnicodeEncodeError: "The JSON output contained non-mappable characters, this is a very "
                                             "strange error, and should be reported to the developer.",

            IOError: "Are you sure that the path is valid, and you have permission to write to that location?",
            PermissionError: IOError,

            # Exceptions from krypton_aes_cbc_encrypt get routed to the krypton_aes_cbc_encrypt entry.
            IvMaskLengthError: ("krypton_aes_cbc_encrypt", IvMaskLengthError),
            InvalidEncryptionInputError: ("krypton_aes_cbc_encrypt", InvalidEncryptionInputError)
        },

        "read_vault": {
            # From read_vault
            InvalidArgumentValueError: "The most likely cause of this error is the password containing non-mappable "
                                       "Unicode characters.",

            InvalidArgumentTypeError: "The most likely cause of this error is a programmer oversight, "
                                      "please report this to the developer.",

            FileNotFoundError: "No vault file at that location could be found, please check your path and try again.",

            PostDecryptionUnicodeDecodeError:
                "The decryption gave an unworkable bad output, the decryption probably failed. Double-check your "
                "password, and the security parameters used to load the vault.",

            PostDecryptionJsonLoadError:
                "The decryption gave an unworkable bad output, the decryption probably failed. "
                "Double-check your password, and the security parameters used to load the vault.",

            IOError: "Are you sure that the path is valid, and you have permission to read from that location?",
            PermissionError: IOError,

            # Exceptions from krypton_aes_cbc_decrypt get routed to the ExtendedAesCbcDecrypt entry.
            IvMaskLengthError: ("krypton_aes_cbc_decrypt", IvMaskLengthError),
            InvalidDecryptionInputError: ("krypton_aes_cbc_decrypt", InvalidDecryptionInputError),
        },

        "vault_integrity_check": {
            IOError: "Are you sure that you have permission to read from that location?",
            PermissionError: IOError
        }
    }

    @staticmethod
    def resolve_exception(function_name: str, exception_type: type, format_values: dict) -> str:
        """Returns the appropriate exception message that matches the exception type and function name.

        Function Parameters
        --------------------
        function_name: str
            The name of the function that threw the exception

        exception_type: type
            The type of the exception that was thrown.

        format_values: dict
            A dictionary containing all required formatting values used to
            format the exception message when the message contains {format}
            syntax. The recommended value is {**locals(), **non_local_values}

        Return Value(s)
        --------------------
        1.) str:
            The formatted exception message.
        """

        if function_name not in ExceptionMessageResolver.Master:
            return None

        resolver: dict = ExceptionMessageResolver.Master[function_name]

        if exception_type not in resolver:
            return "No elaboration is attached to the exception type."

        unformatted_message: str = resolver[exception_type]

        if isinstance(unformatted_message, tuple) and unformatted_message[0] in ExceptionMessageResolver.Master:
            resolver = ExceptionMessageResolver.Master[unformatted_message[0]]

            if unformatted_message[1] not in resolver:
                return "No elaboration is attached to the exception type."
            else:
                unformatted_message = resolver[unformatted_message[1]]

        if isinstance(unformatted_message, type) and unformatted_message in resolver:
            unformatted_message = resolver[unformatted_message]

        required_fields: list = [field_name for _, field_name, _, _ in Formatter().parse(unformatted_message) if
                                 field_name]
        formatter_dictionary: dict = {k: format_values[k] for k, v in required_fields if k in format_values}

        return unformatted_message.format(**formatter_dictionary)


def basic_exception_details(exception: Exception) -> str:
    """Used throughout the program to render basic exception information from the given exception.

    Function Parameters
    --------------------
    exception: Exception
        The exception whose typename and message should be included in the rendered string.

    Return Value(s)
    --------------------
    1.) str:
        The string containing the basic exception details.
    """

    return "Basic exception details: {0}:{1}".format(type(exception), str(exception))


def clear_console(newlines: int = 100) -> None:
    """A dirty yet effective cross-platform function to clear the console.

    Attempts to call the respective clear function of the OS as identified
    by the os.name() function. If the OS cannot be determined, then newlines
    are dumped to the console instead.

    Function Parameters
    --------------------
    newlines: int = 100
        The amount of newlines to dump into the console if the OS cannot be determined,
        and an alternative clearing method is required.
    """

    # Windows/DOS Based Systems
    if os.name in ("nt", "dos", "ce"):
        os.system("cls")

    # Unix Based Systems
    elif os.name in ("posix",):
        os.system("clear")

    # Unknown Operating System
    else:
        print("\n" * newlines)


def apply_pkcs7_padding(data: bytes, multiple: int = 16) -> bytes:
    """Applies Pkcs7 padding to 'data' around a given multiple.

    Function Parameters
    --------------------
    data: bytes
        A sequence of bytes that should be padded.

    multiple: int
        The multiple that should be used for padding,
        e.g. length 14 multiple 16 pads to 16, but
        length 17 multiple 16 pads to 32.

    Return Value(s)
    --------------------
    1.) bytes:
        The Pkcs7 padded data. If the length of the unpadded data is already
        a multiple of 'multiple' then the original data is returned unpadded.
    """

    if not isinstance(data, bytes):
        raise TypeError("Argument 'data' is of an invalid type; expected {0} got {1}".format(bytes, type(data)))

    if not isinstance(multiple, int):
        raise TypeError("Argument 'multiple' is of an invalid type; expected {0} got {1}".format(int, type(multiple)))

    delta: int = multiple - (len(data) % multiple)

    if delta != multiple:
        return data + bytes([delta] * delta)
    else:
        return data


def strip_pkcs7_padding(data: bytes) -> bytes:
    """Strips Pkcs7 padding from 'data' if present.

    Function Parameters
    --------------------
    data: bytes
        The sequence of bytes that should be de-padded.

    Return Value(s)
    --------------------
    1.) bytes:
        The data that has been stripped of Pkcs7 padding. If the data did not
        contain Pkcs7 padding, then the original data is returned unmodified.
    """

    if not isinstance(data, bytes):
        raise TypeError("Argument 'data' is of an invalid type; expected {0} got {1}".format(bytes, type(data)))

    delta: int = data[-1]

    if len(data) >= delta and all(map(lambda byte: byte == delta, data[-delta:])):
        return data[0:-delta]

    return data


def perform_sha512_iterations(data: bytes, iterations: int) -> bytes:
    digest: bytes = data

    for i in range(0, iterations):
        digest = hashlib.new("sha512", digest).digest()

    return digest


def derive_aes_cipher_key(underived_key: bytes) -> bytes:
    argon2_secret: bytes = perform_sha512_iterations(data=underived_key, iterations=2048)
    argon2_salt: bytes = perform_sha512_iterations(data=argon2_secret, iterations=2048)

    return argon2.low_level.hash_secret_raw(
        secret=argon2_secret,
        salt=argon2_salt,
        time_cost=16,
        memory_cost=1024 * 32,
        parallelism=4,
        hash_len=32,
        type=argon2.Type.ID
    )


def krypton_aes_cbc_encrypt(data: bytes, underived_key: bytes, iv_mask_length: int = AES.block_size) -> bytes:
    """Wrapper around PyCryptoDome's AES-CBC encryption function with extended functionality.

    This wrapper function utilizes an IV mask in order to mitigate the problem of having
    to store and transfer IV's. An IV mask is a random sequence of bytes that must be of
    length 16 or greater (AES.block_size) which is added to the input data before being
    encrypted, and removed from the output data after decryption. This ensures that the
    actual input data will not be XOR'd with the random IV, as the IV will only affect
    the first 16 bytes which have been made random, and therefore the IV is not needed
    and decryption is allowed to fail for the first 16 bytes because the data decrypted
    is inconsequential, and can later be stripped from the output.

    The derive_aes_cipher_key() function is used to transform the underived_key parameter
    into a key usable by AES.

    The data is also Pkcs7 padded automatically.

    Function Parameters
    --------------------
    data: bytes
        The unencrypted data targeted for AES-CBC encryption.

    underived_key: bytes
        The bytes that will be used to create an AES cipher key using the
        derive_aes_cipher_key function. This should be the .encode()-ded
        plaintext password's bytes.

    Return Value(s)
    --------------------
    1.) bytes:
        The input data that has been encrypted using AES-CBC.

    Possible Exceptions
    --------------------
    - InvalidArgumentTypeError
        A provided argument had an incorrect type.

    - IvMaskLengthError
        The value of 'iv_mask_length' was less than 16.

    - InvalidEncryptionInputError
        Data passed to PyCryptoDome's encrypt function was rejected, most likely as a result of the data
        having been invalidly padded, and whose length does not follow a multiple of AES.block_size
    """

    if not isinstance(data, bytes):
        raise InvalidArgumentTypeError.auto("data", bytes, type(data))

    if not isinstance(underived_key, bytes):
        raise InvalidArgumentTypeError.auto("underived_key", bytes, type(underived_key))

    if not isinstance(iv_mask_length, int):
        raise InvalidArgumentTypeError.auto("iv_mask_length", bytes, type(iv_mask_length))

    if iv_mask_length < AES.block_size:
        raise IvMaskLengthError.auto(iv_mask_length)

    aes_cipher_key: bytes = derive_aes_cipher_key(underived_key)

    iv: bytes = Random.get_random_bytes(AES.block_size)
    aes_cbc_cipher_object: AES = AES.new(aes_cipher_key, AES.MODE_CBC, iv)

    # Prepare the data for encryption, by adding the IV mask to the input, and then applying Pkcs7 padding, and
    data = apply_pkcs7_padding(Random.get_random_bytes(iv_mask_length) + data, 16)

    try:
        data = aes_cbc_cipher_object.encrypt(data)
    except ValueError as e:
        raise InvalidEncryptionInputError.auto() from e

    return data


def krypton_aes_cbc_decrypt(data: bytes, underived_key: Union[bytes, str], iv_mask_length: int = AES.block_size) -> bytes:
    """Wrapper around PyCryptoDome's AES-CBC decryption function with extended functionality.

    This wrapper function utilizes an IV mask in order to mitigate the problem of having
    to store and transfer IV's. An IV mask is a random sequence of bytes that must be of
    length 16 or greater (AES.block_size) which is added to the input data before being
    encrypted, and removed from the output data after decryption. This ensures that the
    actual input data will not be XOR'd with the random IV, as the IV will only affect
    the first 16 bytes which have been made random, and therefore the IV is not needed
    and decryption is allowed to fail for the first 16 bytes because the data decrypted
    is inconsequential, and can later be stripped from the output.

    The derive_aes_cipher_key() function is used to transform the underived_key parameter
    into a key usable by AES.

    The data is also Pkcs7 de-padded automatically.

    Function Parameters
    --------------------
    data: bytes
        The encrypted data targeted for AES-CBC decryption.

    key: bytes, or str
        The underived cipher key argument that will be provided to krypton_aes_cbc_decrypt().
        This should be the bytes of the plaintext password, though it can also be a str, in
        which case the .encode() method will be called on it.

    iv_mask_length: int = AES.block_size
        The length of the IV mask that should be stripped from the decryption output
        before being returned. If no IV mask was used during encryption, then this
        can be set to 0, otherwise it must be greater or equal to 16.

    Return Value(s)
    --------------------
    1.) bytes:
        The input data that has been decrypted using AES-CBC.

    Possible Exceptions
    --------------------
    - InvalidArgumentTypeError
        A provided argument had an incorrect type.

    - IvMaskLengthError
        The value of 'iv_mask_length' was less than 16.

    - InvalidDecryptionInputError
        Data passed to PyCryptoDome's decrypt function was rejected, most likely as a result of
        attempting to decrypt non-encrypted data whose length isn't a multiple of AES.block_size
    """

    if not isinstance(data, bytes):
        raise InvalidArgumentTypeError.auto("data", bytes, type(data))

    if not isinstance(underived_key, bytes):
        raise InvalidArgumentTypeError.auto("underived_key", bytes, type(underived_key))

    if not isinstance(iv_mask_length, int):
        raise InvalidArgumentTypeError.auto("iv_mask_length", int, type(iv_mask_length))

    if iv_mask_length < AES.block_size:
        raise IvMaskLengthError.auto(iv_mask_length)

    aes_cipher_key: bytes = derive_aes_cipher_key(underived_key)

    iv: bytes = Random.get_random_bytes(AES.block_size)
    cipher: AES = AES.new(aes_cipher_key, AES.MODE_CBC, iv)

    try:
        data = cipher.decrypt(data)
    except ValueError as e:
        raise InvalidDecryptionInputError.auto() from e

    return strip_pkcs7_padding(data)[iv_mask_length:]


def read_vault(file_path: str, underived_key: Union[bytes, str], iv_mask_length: int = AES.block_size) -> dict:
    """Loads a specified vault file into a dictionary, using the given decryption parameters.
    Validate Arguments -> Read File -> AES Decrypt -> UTF-8 Decode -> Json Parse -> Return Dictionary

    Function Parameters
    --------------------
    file_path: str
        The path pointing to the vault file that should be loaded.

    underived_key: bytes, or str
        The underived cipher key argument that will be provided to krypton_aes_cbc_decrypt().
        This should be the bytes of the plaintext password, though it can also be a str, in
        which case the .encode() method will be called on it.

    iv_mask_length: int = AES.block_size
        The IV mask length argument that will be provided to krypton_aes_cbc_decrypt()

    Return Value(s)
    --------------------
    1.) dict:
        The dictionary containing the vault data that was loaded from the file.

    Possible Exceptions
    --------------------
    i.) Any exceptions raised by krypton_aes_cbc_decrypt, check function docstring for more info.

    - InvalidArgumentValueError
        As a result of an argument (namely the 'underived_key' argument) having a problematic value.
        Re-raised from UnicodeEncodeError if raised by str.encode()

    - InvalidArgumentTypeError
        As a result of an argument being of an invalid type, applies to all arguments.

    - FileNotFoundError
        As a result of 'filepath' pointing to an invalid location.

    - PostDecryptionUnicodeDecodeError
        As a result of the decryption output being non-mappable by Unicode, indicating a failed decryption.
        Re-raised from UnicodeDecodeError if raised by bytes.decode()

    - PostDecryptionJsonLoadError
        As a result of the decryption output being non-loadable by JSON, indicating a failed decryption.
        Re-raised from json.JSONDecodeError if raised by json.loads()
    """

    # Argument Validation Step
    # --------------------------------------------------
    if not isinstance(file_path, str):
        raise InvalidArgumentTypeError.auto("file_path", str, type(file_path))

    if isinstance(underived_key, str):
        try:
            underived_key = underived_key.encode()
        except UnicodeEncodeError as e:
            raise InvalidArgumentValueError("Argument 'underived_key' is a string which contains one or more characters"
                                            " that cannot be encoded into a byte sequence.") from e

    # Read From File
    # --------------------------------------------------
    with open(file_path, "rb") as io:
        file_bytes: bytes = io.read()
        io.close()

    # Optional Decryption Step
    # --------------------------------------------------
    if underived_key is not None:
        file_bytes = krypton_aes_cbc_decrypt(file_bytes, underived_key, iv_mask_length)

    # UTF-8 Decoding Step
    # --------------------------------------------------
    try:
        vault_data_json: str = file_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise PostDecryptionUnicodeDecodeError.auto() from e

    # JSON Loading Step
    # --------------------------------------------------
    try:
        vault_data: dict = json.loads(vault_data_json)
    except json.JSONDecodeError as e:
        raise PostDecryptionJsonLoadError.auto() from e

    return vault_data


def write_vault(vault_data: dict, file_path: str, underived_key: Union[bytes, str],
                iv_mask_length: int = AES.block_size, overwrite: bool = False) -> (int, str):
    """Writes the vault data to a vault file using the given encryption parameters.

    This function is an abstraction of the following series of steps:
    Validate Arguments -> Json Serialize Credentials -> UTF-8 Encode -> Aes Encrypt -> Write To File

    Function Parameters
    --------------------
    vault_data: dict
        The dictionary containing the vault data that should be written to the vault file.

    file_path: str
        The path pointing to the vault file that should be written to.

    underived_key: bytes, or str
        The encryption key argument that will be provided to krypton_aes_cbc_decrypt.
        This should be the bytes of the plaintext password, though it can also be a
        str, in which case the .encode() method will be called on it.

    iv_mask_length: int = AES.block_size
        The IV mask length argument that will be provided to krypton_aes_cbc_decrypt

    overwrite: bool = False
        Specifies whether the function has permission to overwrite an existing file.
        If an attempt is made to overwrite when this is False, a FileExistsError is raised.

    Return Value(s)
    --------------------
    1.) int:
        The amount of bytes that have been written to the vault file.

    2.) str:
        The SHA256 digest of the data that was written to the vault file.

    Possible Exceptions
    --------------------------------------------------
    i.) Any exceptions raised by krypton_aes_cbc_encrypt, check function docstring for more info.

    - InvalidArgumentValueError
        As a result of an argument (namely the 'key' argument) having a problematic value.
        Re-raised from UnicodeEncodeError if raised by str.encode()

    - InvalidArgumentTypeError
        As a result of an argument being of an invalid type, applies to all arguments.

    - FileExistsError
        As a result of the 'filepath' argument pointing to an existing file while the 'overwrite' argument is set to False.

    - PreEncryptionJsonDumpError
        As a result of the 'vault_data' dictionary containing a value whose type is not JSON serializable.
        Re-raised from TypeError if raised by json.dumps()

    - PreEncryptionUnicodeEncodeError
        As a result of json.dumps() giving an output containing a character that cannot be mapped to a byte using Unicode/UTF-8.
        This is a very rare error, but is not impossible as characters could be stored in Python memory using a different charset
        than the one being used to encode the characters into bytes, still, this remains highly unlikely.
        Re-raised from UnicodeEncodeError if raised by str.encode()
    """

    # Argument Validation Step
    # --------------------------------------------------
    if not isinstance(vault_data, dict):
        raise InvalidArgumentTypeError.auto("vault_data", dict, type(vault_data))

    if os.path.isfile(file_path) and not overwrite:
        raise FileExistsError("File '{0}' already exists, will not overwrite when overwrite=False".format(file_path))

    if isinstance(underived_key, str):
        try:
            underived_key = underived_key.encode()
        except UnicodeEncodeError as e:
            raise InvalidArgumentValueError("Argument 'key' is a string which contains one or more characters that "
                                            "cannot be encoded into a byte sequence.") from e

    # JSON Dumping Step
    # --------------------------------------------------
    try:
        file_json: str = json.dumps(vault_data)
    except TypeError as e:
        raise TypeError("{0}\nThe vault_data argument in write_vault cannot be JSON serialized."
                        " Cannot write vault file without data.".format(e)) from e

    # UTF-8 Encoding Step
    # --------------------------------------------------
    try:
        file_bytes: bytes = file_json.encode()
    except UnicodeEncodeError as e:
        e.reason += "\nThe serialized JSON vault data cannot be encoded with the UTF8 charset." \
                    " There are non-UTF8 characters inside of the vault."
        raise e

    # Optional Encryption Step
    # --------------------------------------------------
    if underived_key is not None:
        file_bytes = krypton_aes_cbc_encrypt(data=file_bytes,
                                             underived_key=underived_key,
                                             iv_mask_length=iv_mask_length)

    # Write To File
    # --------------------------------------------------
    with open(file_path, "wb+") as io:
        bytes_written: int = io.write(file_bytes)
        io.close()

    return bytes_written, hashlib.sha256(file_bytes).hexdigest()


def render_vault_viewer(vault_data: dict, page_number: int = 0, page_rows: int = 10,
                        account_index_selection: int = None, entry_index_selection: int = None) -> (str, str, str):

    """Renders the vault viewer, used for browsing through, navigating, and making selections in the vault.

    This is used primary to display the accounts, and account entries inside a vault,
    by rendering it in ASCII. It can also be used to select accounts and entries, by
    providing indexes for the account and or entry that should be selected. These
    indexes match the indexes that are seen on the ASCII render. Any selections made
    will be returned.

    Function Parameters
    --------------------
    vault_data: dict
        The vault data that the vault viewer should render.

    page_number: int = 0
        The page number that should be displayed, relative to page_rows.

    page_rows: int = 10
        The amount of rows to display per page. Increasing this value will
        consequently decrease the amount of pages.

    account_index_selection: int = None
        The index of an account that should be selected in the viewer.
        Having this value set to None clears the selection.

    entry_index_selection: int = None
        The index of an account entry that should be selected in the viewer.

    Return Value(s)
    --------------------
    1.) str:
        The ASCII render of the vault viewer.

    2.) str:
        The name of the vault account that was selected using account_index_selection.

    3.) str:
        The name of the vault account entry that was selected using entry_index_selection.
    """

    rendered_lines_buffer: list = []

    index_map: list = list(vault_data)  # Turning a dict into a list only stores the dict's keys, and not its values.

    page_start_index: int = page_number * page_rows
    page_end_index: int = (
        len(index_map) if page_start_index + page_rows >= len(index_map) else page_start_index + page_rows)

    account_selection, entry_selection = None, None

    if page_start_index < len(index_map):
        page_keys: list = index_map[page_start_index:page_end_index]

        for index in range(page_start_index, page_end_index):
            key = index_map[index]

            if index == account_index_selection:
                sub_keys: list = list(vault_data[key])
                account_selection = key

                rendered_lines_buffer.append("|-> ({0}) {1}".format(index, key))

                for sub_index, sub_key in enumerate(sub_keys):
                    if sub_index == entry_index_selection:
                        entry_selection = sub_key
                        rendered_lines_buffer.append(
                            "|----> ({0}-{1}) >> {2}={3}".format(index, sub_index, sub_key, vault_data[key][sub_key]))
                    else:
                        rendered_lines_buffer.append(
                            "|     ({0}-{1}) >> {2}={3}".format(index, sub_index, sub_key, vault_data[key][sub_key]))
            else:
                rendered_lines_buffer.append("|    ({0}) {1}".format(index, key))

    return "\n".join(rendered_lines_buffer), account_selection, entry_selection


def render_dict_diff(old_values: dict, new_values: dict) -> str:
    """Renders an ASCII diff of the values between two dictionaries.

    Function Parameters
    --------------------
    old_values: dict
        The original dictionary that should be compared against.

    new_values: dict
        The modified dictionary that should be compared from.

    Return Value(s)
    --------------------
    1.) str:
        The rendered ASCII diff string
    """

    render_lines_buffer: list = []

    for k, v in new_values.items():
        if k not in old_values:
            render_lines_buffer.append(" [+] {0}".format(k))

            for sk, sv in v.items():
                render_lines_buffer.append(" [+] {0}/{1}".format(k, sk))
        else:
            for sk, sv in v.items():
                if sk not in old_values[k]:
                    render_lines_buffer.append(" [+] {0}/{1}".format(k, sk))
                else:
                    if sv != old_values[k][sk]:
                        render_lines_buffer.append(" [~] {0}/{1}".format(k, sk))

    for k, v in old_values.items():
        if k not in new_values:
            render_lines_buffer.append(" [-] {0}".format(k))

            for sk, sv in v.items():
                render_lines_buffer.append(" [-] {0}/{1}".format(k, sk))
        else:
            for sk, sv in v.items():
                if sk not in new_values[k]:
                    render_lines_buffer.append(" [-] {0}/{1}".format(k, sk))

    return "\n".join(render_lines_buffer)


def generate_random_password(character_classes: list, size: int) -> str:
    """Generates a random password of a given size using the provided character classes.

    This random password generator places emphasis on every character class having an equal
    chance of appearing in the output, so character classes with more characters, e.g. the
    alphabet containing more characters than digits 0-9, will appear with same frequency.

    Function Parameters
    --------------------
    character_classes: list
        A list of character classes to be used when generating the password.
        Character classes are strings that can be one of the following
         : alpha, lower, upper, numerical, special, extra

        If a string is provided that isn't one of these character classes,
        the string's characters will be interpreted as the character class.

    size: int
        The length of the password to be generated.

    Return Value(s)
    --------------------
    1.) str:
        The randomly generated password.

    Possible Exceptions
    --------------------
    InvalidArgumentTypeError
        As a result of a provided argument having an invalid type.

    ValueError
        As a result of no character sequences being available for a password to be generated.
    """

    if not hasattr(character_classes, "__iter__"):
        raise TypeError("The value provided for 'character_classes' is not iterable, must be list, tuple, etc")

    if not isinstance(character_classes, list):
        raise InvalidArgumentTypeError.auto("sequences", list, type(character_classes))

    if not isinstance(size, int):
        raise InvalidArgumentTypeError.auto("size", int, type(size))

    character_sequences: list = []

    none_in = lambda source, target: all(map(lambda e: e not in target, source))

    for sequence in character_classes:
        if sequence == "alpha" and none_in((ascii_letters, ascii_lowercase, ascii_uppercase), character_sequences):
            character_sequences.append(ascii_letters)

        elif sequence == "lower" and none_in((ascii_lowercase, ascii_uppercase, ascii_letters), character_sequences):
            character_sequences.append(ascii_lowercase)

        elif sequence == "upper" and none_in((ascii_lowercase, ascii_uppercase, ascii_letters), character_sequences):
            character_sequences.append(ascii_uppercase)

        elif sequence == "numerical" and ascii_digits not in character_sequences:
            character_sequences.append(ascii_digits)

        elif sequence == "special" and none_in((ascii_special, "!#$%&*+-=?@^_|"), character_sequences):
            if "extra" in character_classes:
                character_sequences.append(ascii_special)
            else:
                character_sequences.append("!#$%&*+-=?@^_|")

        elif isinstance(sequence, str):
            character_sequences.append(sequence)

    if not len(character_sequences):
        raise ValueError("There are no character sequences that a password can be generated with.")

    return "".join(map(lambda _: random.choice(random.choice(character_sequences)), range(size)))


def vault_integrity_check(file_path: str, test_hash: str) -> bool:
    """ Performs a SHA256 integrity check against a known hash.
    The results of the integrity check are printed to the standard output.

    Function Parameters
    --------------------
    file_path: str
        The path to the file whose integrity should be checked.

    test_hash: str
        The SHA256 hash that the file should match for the integrity check to pass.

    Return Value(s)
    --------------------
    1.) bool:
        True if integrity check was passed, false if not.
    """

    with open(file_path, "rb") as io:
        data: bytes = io.read()
        io.close()

    file_hash: str = hashlib.sha256(data).hexdigest()

    print("-" * 50)
    print("RAM  HASH (sha256):", test_hash)
    print("DISK HASH (sha256):", file_hash)
    print("-" * 50)

    if test_hash == file_hash:
        print("Integrity Check Passed\n")
        return True
    else:
        print("INTEGRITY CHECK FAILED !!")
        print("There is a conflict between the data in memory and the data on the disk, data not properly saved!")
        print("To preserve the data stored in memory, consider one of the following suggestions..", end="\n\n")

        print("1.) Try writing the file again, maybe another process was using the file (e.g. Dropbox), and had a"
              " handle to the file pending to close.")

        print("2.) Use the write command rather than the save command, to write the file to a different location"
              " (maybe this is a permission issue?)")

        print("3.) Use the dumpjson command to dump the unencrypted JSON data into your clipboard, store it in a file, "
              "and use the --insecure flag to load it and then re-encrypt it using make-secure.")

        return False


if __name__ == "__main__":
    argp = argparse.ArgumentParser()

    argp.add_argument(
        "--file", "-f",
        action="store",
        nargs="?",
        required=True,
        type=lambda argument: os.path.abspath(argument),
        help="A path pointing to the vault file that should be created or loaded.",
        dest="vault_path",
    )

    argp.add_argument(
        "--ivmask", "-ivm",
        action="store",
        nargs="?",
        default=16,
        type=int,
        required=False,
        help="The amount of random bytes that should be added or stripped from the start of the encryption/decryption "
             "output in order to mask the IV; should be 16 at the very least (AES block size)",
        dest="iv_mask_length"
    )

    argp.add_argument(
        "--insecure", "-is",
        action="store_true",
        default=False,
        required=False,
        help="When present, this flag makes the program treat the file pointed to by --file as an unencrypted insecure "
             "vault, decryption will not be attempted. This also affects the encryption of newly created vaults.",
        dest="insecure_mode"
    )

    argp.add_argument(
        "--debug", "-db",
        action="store_true",
        default=False,
        required=False,
        help="This flag enables the printing of additional information for debugging purposes.",
        dest="debug_mode"
    )

    pargs = argp.parse_args()

    if not os.path.isfile(pargs.vault_path):
        print("The vault file '{0}' doesn't exist yet, create a new vault file at "
              "that location?".format(pargs.vault_path))

        if input("Y/N >> ").lower() in ("y", "yes"):
            password: str = getpass.getpass() if not pargs.insecure_mode else None

            try:
                wrote = write_vault(vault_data={},
                                    file_path=pargs.vault_path,
                                    underived_key=password,
                                    iv_mask_length=pargs.iv_mask_length)

            except Exception as e:
                print("-" * 50)
                print("Failure when attempting to write vault to location '{0}'".format(pargs.vault_path))
                print(ExceptionMessageResolver.resolve_exception("write_vault", type(e), {**pargs.__dict__, **locals()}))
                print(basic_exception_details(e))
                print("-" * 50)

                if pargs.debug_mode:
                    raise e
                else:
                    print("Use the --debug flag to view the exception traceback.")
                    raise SystemExit

            print("Wrote", wrote, "bytes to", pargs.vault_path, end="\n\n")

        else:
            raise SystemExit

    if not os.path.isfile(pargs.vault_path):
        print("Cannot find vault file '{0}'".format(pargs.vault_path))
        raise SystemExit

    print("Loading vault..", pargs.vault_path)

    password: Union[str, None] = None

    if not pargs.insecure_mode:
        password = getpass.getpass()

    try:
        vault_data: dict = read_vault(file_path=pargs.vault_path,
                                      underived_key=password,
                                      iv_mask_length=pargs.iv_mask_length)
    except Exception as e:
        print("-" * 50)
        print("Failure when attempting to read from vault at location '{0}'".format(pargs.vault_path))
        print(ExceptionMessageResolver.resolve_exception("read_vault", type(e), {**pargs.__dict__, **locals()}))
        print(basic_exception_details(e))
        print("-" * 50)

        if pargs.debug_mode:
            raise e
        else:
            print("Use the --debug flag to view the exception traceback.")
            raise SystemExit

    # A deep copy of the vault_data dict, used to keep track of the
    # original values before any modifications were made. The diff
    # command uses this, as well as the restore command. This value
    # is re-assigned when using the save command to save changes.
    vault_data_backup: dict = copy.deepcopy(vault_data)

    # Stores the filtered version of the vault_data dict when using
    # the filter command to filter accounts by search terms.
    filtered_vault_data: dict = Union[dict, None]

    # Stores the list of search terms used to filter the vault_data
    # dictionary with. The matching results get stored into the above
    # filtered_vault_data dictionary. If this value is None, that is
    # interpreted as not having any search filters active. This is set
    # to None by the clearfilter command.
    render_search_filter: list = Union[list, None]

    # Tracks the current page number that should be rendered. Changed
    # whenever the page is changed using the page switching command.
    render_page_number: int = 0

    # Determines how many rows of accounts should be rendered per page,
    # and therefore also determines the amount of pages in total, as
    # whenever a page is full, the remaining rows overflow to the next.
    render_page_rows: int = 20

    # Keeps track of the selected account's index that was selected using
    # the select command. When this value is None, that is interpreted as
    # nothing being currently selected. This is set to None when using the
    # clear selection command.
    render_selected_account_index: Union[int, None] = None

    # Keeps track of the selected entry's index that was selected using
    # the select command. When this value is None, that is interpreted as
    # nothing being currently selected. This is set to None when using the
    # clear selection command.
    render_selected_entry_index: Union[int, None] = None

    # Keeps track of the vault's security state as changed by make-secure
    # or make-insecure. By default, this is set to the resulting value of
    # the --insecure command line argument, which by default is False.
    vault_insecure_mode: bool = pargs.insecure_mode

    # Primary Command Processing And Rendering Loop
    # ----------------------------------------------------------------------------------------------------
    while True:
        os.system("cls")

        print("-" * 50)
        print("| {0}: ARGON 2, AES-256, IV-MASK: {1}".format(
            "Insecure" if vault_insecure_mode else "Secure", pargs.iv_mask_length))
        print("-" * 50)

        if isinstance(render_search_filter, list):
            filtered_vault_data = {k: v for (k, v) in vault_data.items() if
                                   any(map(lambda f: f.lower() in k.lower(), render_search_filter))}

            rendered_vault_data, selected_key, selected_subkey = render_vault_viewer(filtered_vault_data,
                                                                                     render_page_number,
                                                                                     render_page_rows,
                                                                                     render_selected_account_index,
                                                                                     render_selected_entry_index)
            print(rendered_vault_data)
        else:
            filtered_vault_data = None
            rendered_vault_data, selected_key, selected_subkey = render_vault_viewer(vault_data, render_page_number,
                                                                                     render_page_rows,
                                                                                     render_selected_account_index,
                                                                                     render_selected_entry_index)
            print(rendered_vault_data)

        print("-" * 50)
        print("| Page {0} / {1}".format(render_page_number, (
            len(filtered_vault_data) if filtered_vault_data else len(vault_data)) // render_page_rows))
        print("-" * 50)

        if filtered_vault_data:
            print("Filters: any({0})".format(render_search_filter))
            print("-" * 50)

        command = input("Command: ")
        command_split = command.split(" ")

        for index, cmd in enumerate(command_split):
            next_cmd = command_split[index + 1] if index + 1 < len(command_split) else None

            # Page Selection
            # --------------------------------------------------
            if cmd.isdigit() and len(command_split) == 1:
                render_page_number = int(cmd)

            # Show Command Reference Text
            # --------------------------------------------------
            if cmd in ("help", "?", "what"):
                print(COMMAND_REFERENCE_TEXT)
                input("Press enter to continue...")

            # Restore Vault Backup / Revert Changes
            # --------------------------------------------------
            elif cmd in ("restore", "revert"):
                print("-" * 50)
                print(render_dict_diff(vault_data_backup, vault_data))
                print("-" * 50)

                print("You are about to revert these changes in memory, any modifications you made "
                      "will be lost unless saved.")

                print("Confirm that you want to revert these changes?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                vault_data = copy.deepcopy(vault_data_backup)
                print("Changes have been reverted.")
                input("Press enter to continue..")

            # JSON Vault Dump Command
            # --------------------------------------------------
            elif cmd in ("dumpjson",):
                print("Are you sure you want to dump your entire vault as unencrypted JSON into your terminal?")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                print("-" * 50)
                print(json.dumps(vault_data, indent=4))
                print("-" * 50)

                input("Press enter to continue..")

            # Convert Unencrypted Vault To Encrypted Vault
            # --------------------------------------------------
            elif cmd in ("make-secure",):
                if not vault_insecure_mode:
                    print("The vault is already set to secure mode, use this command to convert an "
                          "insecure vault to a secure vault.")

                    input("Press enter to continue..")
                    continue

                print("You are about to convert your vault from an insecure plaintext vault into "
                      "a secure AES-CBC encrypted vault.")

                print("Until you save the vault using the save command, this will not affect the vault on your disk.")
                print("Confirm that you want to switch the vault mode from insecure to secure?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                new_password: str = getpass.getpass("New Password: ")
                again: str = getpass.getpass("Again: ")

                if new_password != again:
                    print("Cancelling operation, the typed passwords do not match.")
                    continue

                password = new_password
                vault_insecure_mode = False

                print("Vault mode has been changed to secure.")
                input("Press enter to continue..")

            # Convert Encrypted Vault To Unencrypted Vault
            # --------------------------------------------------
            elif cmd in ("make-insecure",):
                if vault_insecure_mode:
                    print("The vault is already set to insecure mode, use this command to convert a "
                          "secure vault to an insecure vault.")

                    input("Press enter to continue..")
                    continue

                print("You are about to convert your vault from a secure AES-CBC encrypted vault into an "
                      "insecure plaintext vault.")

                print("Until you save the vault using the save command, this will not affect the vault on your disk.")
                print("Confirm that you want to switch the vault mode from secure to insecure?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                reentered_password: str = getpass.getpass("Re-enter Password: ")

                if reentered_password != password:
                    print("Cancelling operation, re-entered password does not match the original "
                          "password used to decrypt the vault.")

                    input("Press enter to continue..")
                    continue

                password = None
                vault_insecure_mode = True

                print("Vault mode has been changed to insecure.")
                input("Press enter to continue..")

            # Save Vault Changes
            # --------------------------------------------------
            elif cmd in ("save",):
                print("-" * 50)
                print(render_dict_diff(vault_data_backup, vault_data))
                print("-" * 50)
                print("Confirm Diff Changes For Vault '{0}'".format(pargs.vault_path))

                if input("Y/N > ").lower() not in ("y", "yes"):
                    continue

                if not vault_insecure_mode:
                    print("Re-enter Your Password")
                    reentered_password: str = getpass.getpass()

                    if reentered_password != password:
                        print("The entered password doesn't match the password used to decrypt the vault.")
                        print("To change passwords, use write instead of save, and select a new location.")
                        input("Press enter to continue..")
                        continue

                try:
                    wrote, hash_in_ram = write_vault(vault_data=vault_data,
                                                     file_path=pargs.vault_path,
                                                     underived_key=password,
                                                     iv_mask_length=pargs.iv_mask_length,
                                                     overwrite=True)
                except Exception as e:
                    print("-" * 50)
                    print("Failure when attempting to write vault to location '{0}'".format(pargs.vault_path))
                    print(ExceptionMessageResolver.resolve_exception("write_vault", type(e), {**pargs.__dict__, **locals()}))
                    print(basic_exception_details(e))
                    print("-" * 50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")

                    input("Press enter to continue..")
                    continue

                print("\nWrote {0} bytes to '{1}'".format(wrote, pargs.vault_path))

                try:
                    if vault_integrity_check(pargs.vault_path, hash_in_ram):
                        vault_data_backup = copy.deepcopy(vault_data)
                except Exception as e:
                    print("-" * 50)
                    print("Failure when attempting to re-read contents of vault file for the purposes of "
                          "checking its integrity '{0}'".format(pargs.vault_path))

                    print(ExceptionMessageResolver.resolve_exception("vault_integrity_check", type(e), {**pargs.__dict__, **locals()}))
                    print(basic_exception_details(e))
                    print("-" * 50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")

                input("Press enter to continue..")

            # Write Vault To File
            # --------------------------------------------------
            elif cmd in ("write",):
                print("-" * 50)
                new_path: str = input("File Path >> ")
                print("-" * 50)

                if os.path.isfile(new_path):
                    print("Cannot comply, a file with that name already exists. To save your changes, use save.")
                    input("Press enter to continue..")
                    continue

                print("Confirm filepath '{0}'".format(os.path.abspath(new_path)))

                if input("Y/N > ").lower() not in ("y", "yes"):
                    continue

                new_password = None

                if not vault_insecure_mode:
                    new_password: str = getpass.getpass("New Password: ")
                    password_again: str = getpass.getpass("Again: ")

                    if new_password != password_again:
                        print("Passwords do not match, try again")
                        input("Press enter to continue..")
                        continue

                try:
                    wrote, hash_in_ram = write_vault(vault_data=vault_data,
                                                     file_path=os.path.abspath(new_path),
                                                     underived_key=new_password,
                                                     iv_mask_length=pargs.iv_mask_length,
                                                     overwrite=False)
                except Exception as e:
                    print("-" * 50)
                    print("Failure when attempting to write vault to location '{0}'".format(pargs.vault_path))
                    print(ExceptionMessageResolver.resolve_exception("write_vault", type(e), {**pargs.__dict__, **locals()}))
                    print(basic_exception_details(e))
                    print("-" * 50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")

                    input("Press enter to continue..")
                    continue

                print("\nWrote {0} bytes to '{1}'".format(wrote, os.path.abspath(new_path)))

                try:
                    if vault_integrity_check(os.path.abspath(new_path), hash_in_ram):
                        vault_data_backup = copy.deepcopy(vault_data)
                except Exception as e:
                    print("-" * 50)

                    print("Failure when attempting to re-read contents of vault file for "
                          "the purposes of checking its integrity '{0}'".format(pargs.vault_path))

                    print(ExceptionMessageResolver.resolve_exception("vault_integrity_check", type(e), {**pargs.__dict__, **locals()}))
                    print(basic_exception_details(e))
                    print("-" * 50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")

                input("Press enter to continue..")

            # Exit Program
            # --------------------------------------------------
            elif cmd in ("exit", "quit"):
                raise SystemExit

            # Clear Selection
            # --------------------------------------------------
            elif cmd in ("cs", "clearsel", "clearselection"):
                render_selected_account_index = None
                render_selected_entry_index = None

            # Clear Search Filter
            # --------------------------------------------------
            elif cmd in ("cf", "clearfiltr"):
                render_search_filter = None

            # Diff / View Changes
            # --------------------------------------------------
            elif cmd in ("diff",) and len(command_split) == 1:
                print("-" * 50)
                print(render_dict_diff(vault_data_backup, vault_data))
                print("-" * 50)
                input("Press enter to continue..")

            # Copy Selection To Clipboard
            # --------------------------------------------------
            elif cmd in ("cp", "copy"):
                if selected_key is not None and selected_subkey is not None:
                    pyperclip.copy(vault_data[selected_key][selected_subkey])
                    print("Copied text!")
                    time.sleep(0.2)

            # Add Entry To Selected Account
            # --------------------------------------------------
            elif cmd in ("a", "add"):
                if selected_key is not None:
                    print("Adding new key to {0}".format(selected_key))

                    new_kv_key = input("Key: ")

                    if new_kv_key in vault_data[selected_key]:
                        print("Cannot comply, a key with that name under the same account already exists.")
                        input("Press enter to continue..")
                        continue

                    new_kv_val = input("Value: ")

                    print("Confirm addition ({0}) += ({1}:{2})".format(selected_key, new_kv_key, new_kv_val))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        vault_data[selected_key][new_kv_key] = new_kv_val
                else:
                    print("Cannot comply, an account needs to be selected first in order to add a new entry to it.")
                    input("Press enter to continue..")

            # Delete Selected Entry
            # --------------------------------------------------
            elif cmd in ("del", "delete"):
                if selected_key is not None and selected_subkey is not None:
                    print("Confirm deletion ({0} / {1})".format(selected_key, selected_subkey))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        del vault_data[selected_key][selected_subkey]
                else:
                    print("Cannot comply, an entry needs to be selected before it can be deleted.")
                    input("Press enter to continue..")

            # Modify Selected Entry's Value
            # --------------------------------------------------
            elif cmd in ("mod", "modify"):
                if selected_key is not None and selected_subkey is not None:
                    print("Modifying ({0} / {1})".format(selected_key, selected_subkey))
                    new_value = input("New Value: ")

                    print("Confirm modification ({0} / {1}) = {2}".format(selected_key, selected_subkey, new_value))
                    confirmation: bool = input("Y/N > ").lower() in ("yes", "y")

                    if confirmation:
                        vault_data[selected_key][selected_subkey] = new_value
                else:
                    print("Cannot comply, an entry needs to be selected before its value can be modified.")
                    input("Press enter to continue..")

            # Add Account
            # --------------------------------------------------
            elif cmd in ("aac", "addacc"):
                account_name = input("Account Name: ")

                if account_name in vault_data:
                    print("Cannot comply, an account with that name already exists.")
                    input("Press enter to continue..")
                    continue
                else:
                    print("Confirm account addition (vault) += ({0})".format(account_name))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        vault_data[account_name] = {}

            # Delete Selected Account
            # --------------------------------------------------
            elif cmd in ("dac", "delacc"):
                if selected_key is not None:
                    print("Confirm account deletion (vault) -= ({0})".format(selected_key))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        del vault_data[selected_key]
                else:
                    print("Cannot comply, no account has been selected.")
                    input("Press enter to continue..")

            # Commands that rely on follow-up arguments.
            # ----------------------------------------------------------------------------------------------------
            if next_cmd is not None:

                # Account & Entry Selection
                # --------------------------------------------------
                if cmd in ("s", "select") and index == 0:
                    if next_cmd.isdigit():
                        render_selected_account_index = int(next_cmd)

                    elif "-" in next_cmd:
                        next_cmd_split = next_cmd.split("-")

                        if len(next_cmd_split) == 2 and all(map(lambda e: e.isdigit(), next_cmd_split)):
                            render_selected_account_index = int(next_cmd_split[0])
                            render_selected_entry_index = int(next_cmd_split[1])

                # Random Password Generation
                # --------------------------------------------------
                elif cmd in ("rand", "random") and index == 0:
                    if not next_cmd.isdigit():
                        print("Cannot comply, the password length '{0}' is not a valid digit.".format(next_cmd))
                        input("Press enter to continue..")
                        continue

                    if len(command_split) <= 2:
                        print("Cannot comply, character classes haven't been provided.")
                        input("Press enter to continue..")
                        continue

                    if selected_key is None or selected_subkey is None:
                        print(
                            "Cannot comply, an entry must first be selected before a random password can be inserted into it.")
                        input("Press enter to continue..")
                        continue

                    password_length: int = int(next_cmd)
                    random_password: str = generate_random_password(command_split[2:], password_length)
                    vault_data[selected_key][selected_subkey] = random_password

                # Set Display Filter
                # --------------------------------------------------
                elif cmd in ("f", "filter") and index == 0:
                    render_search_filter = command_split[1:]

                # Change Rows Display Count
                # --------------------------------------------------
                elif cmd in ("pr", "rows") and index == 0:
                    if next_cmd.isdigit() and int(next_cmd) > 0:
                        render_page_rows = int(next_cmd)

                # Set Secspec IvMask
                # --------------------------------------------------
                elif cmd in ("ivmask",) and index == 0:
                    if next_cmd.isdigit():
                        pargs.iv_mask_length = int(next_cmd)
                    else:
                        print("Cannot comply, '{0}' is not a valid digit.".format(next_cmd))
                        input("Press enter to continue..")

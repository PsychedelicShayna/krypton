import traceback # Traceback library for printing formatted exception information.
import argparse  # Useful library for parsing command line arguments, and generating automatic helptexts.
import hashlib   # Standard cryptographic hash function library, for.. hashing :)
import getpass   # Secure input library for passwords, hides input.
import random    # Standard library random functions, overriden by PyCryptoDome.
import enum      # Library containing a base class for making enum classes.
import time      # Time library, used for time.sleep()-ing the console.
import copy      # Copy library which can deepcopy a dict.
import json      # JSON Parsing and loading library.
import os        # OS Functions, also contains os.path module.

# Contains ASCII character classes, useful for password generation.
from string import ascii_letters, ascii_uppercase, ascii_lowercase
from string import punctuation as ascii_special
from string import digits as ascii_digits
from string import Formatter

# PyCryptoDome Cryptography Library
from Crypto.Cipher import AES
from Crypto import Random

# Python Clipboard Library
import pyperclip

COMMAND_REFERENCE_TEXT:str = """
This is the command reference for LSPM, here you can find all of the relevant
commands for interacting with this password manager. This does not include the
command line flags, to view those use the --help / -h flag when running LSPM.

Command Reference Legend
--------
N      = Denotes a numerical value, e,g, command [N] (command takes any number as an arugment)
|      = Denotes multiple available options (or)
,      = Denotes list of command aliases.
[]     = Denotes singular parameter, contents indicate type of value.
{...}  = Denotes a space-separated sequence of parameters of the same type.
--------

Navigating LSPM:
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

Performing Edits In LSPM:
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
keyalg [ALG]          | Sets the hash algorithm used to turn the password into an AES-CBC key,
                      | same as --keyalg. Algorithm must be part of hashlib.algorithms_available
                      | Type an invalid algorithm to get shown a list of available algorithms, or use
                      | the --help command to get the same list when the program isn't running.
                      | Example: keyalg sha3_224
----------------------------------------------------------------------------------------------------
keylen [N]            | Sets the encryption key length mode for AES-CBC aka AES-128, AES-196, AES-256
                      | This is the same as using the --keylen argument. Must be one of: 16, 24, 32
                      | Example, for AES-196: keylen 24
----------------------------------------------------------------------------------------------------
ivmask [N]            | Sets the length of the IV mask - the amount of random bytes appended/stripped
                      | from the encryption input/output data in order to guarantee a random output
                      | for the first round of XOR. Must be a minimum of 16 to be secure, but can
                      | be set to any size, though a high value will increase the file size.
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
    def auto(name:str, expected:type, got:type):
        message_format:str = "Argument '{0}' is of an invalid type, expected {1} got {2}"
        return InvalidArgumentTypeError(message_format.format(name, expected, got))

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class InvalidArgumentValueError(ValueError):
    """Error where an argument had an invalid value.
    """

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class InvalidAesKeylenError(ValueError):
    """Invalid AES key length mode, must be 16, 24, 32
    """

    @staticmethod
    def auto(length:int):
        message_format = "Invalid AES key length '{0}', valid key lengths are 16, 24, 32"
        return InvalidAesKeylenError(message_format.format(length))

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class InvalidHashlibAlgError(ValueError):
    """Algorithm was not contained within hashlib.algorithms_available
    """

    @staticmethod
    def auto(algorithm:str):
        message_format = "Invalid hashlib algorithm '{0}', not in hashlib.algorithms_available"
        return InvalidHashlibAlgError(message_format.format(algorithm))

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class IvMaskLengthError(ValueError):
    """Error describing the use of an invalid IV mask length.

    This is typically raised because an IV mask length was used which
    was greater than 0 and less than 16.
    """
    @staticmethod
    def auto(ivmask_len:int):
        message_format:str = "Invalid ivmask length '{0}', must either be >= 16, or 0"
        return IvMaskLengthError(message_format.format(ivmask_len))

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class DigestLengthError(ValueError):
    """Error where an attempt was made to use an algorithm whose output isn't long enough for an AES key.

    This usually happens with older hash algorithms, as their output can be quite small,
    too small to fit into the AES key size range of 16, 24, or 32 bytes.
    """

    @staticmethod
    def auto(alg:str, alglen:int, needlen:int):
        message_format:str = "Output length of the hashlib algorithm '{0}' (len={1}) is less than the required length of {2}"
        return DigestLengthError(message_format.format(alg, alglen, needlen))

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class InvalidDecryptionInputError(ValueError):
    """Error involving invalid decryption input data or invalid decryption parameters.

    An example might be attempting to decrypt a sequence of bytes that aren't encrypted,
    and therefore don't possess the correct size for an attempt at decryption.
    """

    @staticmethod
    def auto():
        message_format:str = "Bad input data was passed to the AES-CBC decryption function, and it threw an exception."
        return InvalidDecryptionInputError(message_format)

    def __str__(self) -> str:
        return self.message

    def __init__(self, message:str):
        self.message = message

class InvalidEncryptionInputError(ValueError):
    """Error involving invalid input data or invalid encryption parameters.

    An example might be might be the use of an invalid key size, or passing a value
    that isn't a sequence of bytes as an input to the encryption.
    """

    @staticmethod
    def auto():
        message_format:str = "Bad input data was passed to the AES-CBC encryption function, and it threw an exception."
        return InvalidEncryptionInputError(message_format)

    def __str__(self) -> str:
        return self.message

    def __init__(self, message:str):
        self.message = message


class PostDecryptionJsonLoadError(json.JSONDecodeError):
    """JSON Decode error that occured after data has been decrypted.

    This generally indicates a decryption failure, as the output was
    unparsable by JSON, but could also indicate invalid source data.
    """

    @staticmethod
    def auto():
        message:str = "JSON Loading error encountered post-decryption, indicating that the decryption output was not JSON parsable."
        return PostDecryptionJsonLoadError(message)

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class PostDecryptionUnicodeDecodeError(UnicodeDecodeError):
    """Unicode decode error that occured after data has been decrypted.

    This generally indicates a decryption failure, as the output contained
    characters unmappable by UTF-8, but could also indicate invalid source data.
    """

    @staticmethod
    def auto():
        message:str = "Unicode decoding error encountered post-decryption, indicating that the decryption output cannot be interpreted as UTF-8 unicode."
        return PostDecryptionUnicodeDecodeError(message)

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message


class PreEncryptionJsonDumpError(TypeError):
    """JSON Dump error that occured before encryption.

    This generally indicates an invalid credentials dictionary.
    """

    @staticmethod
    def auto():
        message:str = "JSON Serialization error encounted pre-encryption, indicating that the target dictionary contained a value whose type cannot be represented in JSON."
        return PreEncryptionJsonDumpError(message)

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message

class PreEncryptionUnicodeEncodeError(UnicodeEncodeError):
    """Unicode encode error that occured before encryption.

    This generally indicates the presence of an unknown unmappable character
    as part of the encryption input.
    """

    @staticmethod
    def auto():
        message:str = "Unicode encoding error encountered pre-encryption, indicating that the string destined for encryption contained a character that could not be mapped into the target encoding."
        return PreEncryptionUnicodeEncodeError(message)

    def __str__(self):
        return self.message

    def __init__(self, message:str):
        self.message = message


class ExceptionMessageResolver():
    """Contains all of the program exception messages that should be presented to the user.

    This point of this class is to generalize the storage of exception messages,
    and allow easy modification and addition of exception messages, as well as
    automatic exception message resolution based on exception source and type.
    """

    Master:dict = {
        "ExtendedAesCbcEncrypt": {
            InvalidAesKeylenError: "An invalid AES-CBC length mode was used ({keylen}) when calling ExtendedAesCbcEncrypt, this should not be possible, please report this to the developer.",
            InvalidHashlibAlgError: "An unsupported hashlib algorithm '{keyalg}' was used when calling ExtendedAesCbcEncrypt, this should nto be possible, please report this to the developer.",
            IvMaskLengthError: "The provided IV mask length ({ivmask_len}) is invalid, it must either be 0 or greater than 16.",
            DigestLengthError: "The output length of the hashlib algorithm '{keyalg}' is insufficient for the selected AES-CBC length mode of {keylen} bytes, use a different algorithm.",
            InvalidEncryptionInputError: "The data passed to ExtendedAesCbcEncrypt was invalid, most likely as a result of a padding error, please report this to the developer."
        },

        "ExtendedAesCbcDecrypt": {
            InvalidAesKeylenError: "An invalid AES-CBC length mode was used ({keylen}) when calling ExtendedAesCbcDecrypt, this should not be possible, please report this to the developer.",
            InvalidHashlibAlgError: "An unsupported hashlib algorithm '{keyalg}' was used when calling ExtendedAesCbcDecrypt, this should nto be possible, please report this to the developer.",
            IvMaskLengthError: "The provided IV mask length ({ivmask_len}) is invalid, it must either be 0 or greater than 16.",
            DigestLengthError: "The output length of the hashlib algorithm '{keyalg}' is insufficient for the selected AES-CBC length mode of {keylen} bytes, use a different algorithm.",
            InvalidDecryptionInputError: "An attempt was made to decrypt invalid data, most likely because the vault is insecure & unencrypted, or because the file is not a vault."
        },

        "WriteVault": {
            # From WriteVault
            InvalidArgumentValueError: "The most likely cause of this error is the password contaning non-mappable Unicode characters.",
            InvalidArgumentTypeError: "The most likely cause of this error is a programmer oversight, please report this to the developer.",
            FileExistsError: "A vault at that location already exists, and overwrite is disabled for this operation.",
            PreEncryptionJsonDumpError: "Failed turn the empty credentials template dictionary into JSON, this is most likely a programmer oversight, please report this to the developer.",
            PreEncryptionUnicodeEncodeError: "The JSON output contained non-mappable characters, this is a very strange error, and should be reported to the developer.",
            IOError: "Are you sure that the path is valid, and you have permission to write to that location?",
            PermissionError: IOError,

            # Exceptions from ExtendedAesCbcEncrypt get routed to the ExtendedAesCbcEncrypt entry.
            InvalidAesKeylenError: ("ExtendedAesCbcEncrypt", InvalidAesKeylenError),
            InvalidHashlibAlgError: ("ExtendedAesCbcEncrypt", InvalidHashlibAlgError),
            IvMaskLengthError: ("ExtendedAesCbcEncrypt", IvMaskLengthError),
            DigestLengthError: ("ExtendedAesCbcEncrypt", DigestLengthError),
            InvalidEncryptionInputError: ("ExtendedAesCbcEncrypt", InvalidEncryptionInputError)
        },

        "ReadVault": {
            # From ReadVault
            InvalidArgumentValueError: "The most likely cause of this error is the password contaning non-mappable Unicode characters.",
            InvalidArgumentTypeError: "The most likely cause of this error is a programmer oversight, please report this to the developer.",
            FileNotFoundError: "No vault file at that location could be found, please check your path and try again.",
            PostDecryptionUnicodeDecodeError: "The decryption gave an unworkable bad output, the decryption probably failed. Double-check your password, and the security parameters used to load the vault.",
            PostDecryptionJsonLoadError: "The decryption gave an unworkable bad output, the decryption probably failed. Double-check your password, and the security parameters uised to load the vault.",
            IOError: "Are you sure that the path is valid, and you have permission to read from that location?",
            PermissionError: IOError,

            # Exceptions from ExtendedAesCbcDecrypt get routed to the ExtendedAesCbcDecrypt entry.
            InvalidAesKeylenError: ("ExtendedAesCbcDecrypt", InvalidAesKeylenError),
            InvalidHashlibAlgError: ("ExtendedAesCbcDecrypt", InvalidHashlibAlgError),
            IvMaskLengthError: ("ExtendedAesCbcDecrypt", IvMaskLengthError),
            DigestLengthError: ("ExtendedAesCbcDecrypt", DigestLengthError),
            InvalidDecryptionInputError: ("ExtendedAesCbcDecrypt", InvalidDecryptionInputError),
        },

        "IntegrityCheck": {
            IOError: "Are you sure that you have permission to read from that location?",
            PermissionError: IOError
        }
    }

    @staticmethod
    def Resolve(funcname:str, exceptiont:type, formatvalues:dict) -> str:
        """Returns the appropriate exception message that matches the exception type and function name.

        Function Parameters
        --------------------
        funcname:str
            The name of the function that threw the exception

        exceptiont:type
            The type of the exception that was thrown.

        formatvalues:dict
            A dictionary containing all of the required formatting values used
            to format the exception message when the message contains {format}
            syntax. The recommended value is {**locals(), **non_local_values}

        Return Value(s)
        --------------------
        1.) str:
            The formatted exception message.
        """

        if funcname not in ExceptionMessageResolver.Master:
            return None

        resolver:dict = ExceptionMessageResolver.Master[funcname]

        if exceptiont not in resolver:
            return "No elaboration is attached to the exception type."

        unformatted_message:str = resolver[exceptiont]

        if isinstance(unformatted_message, tuple) and unformatted_message[0] in ExceptionMessageResolver.Master:
            resolver = ExceptionMessageResolver.Master[unformatted_message[0]]

            if unformatted_message[1] not in resolver:
                return "No elaboration is attached to the exception type."
            else:
                unformatted_message = resolver[unformatted_message[1]]

        if isinstance(unformatted_message, type) and unformatted_message in resolver:
            unformatted_message = resolver[unformatted_message]

        required_fields:list = [field_name for _, field_name, _, _ in Formatter().parse(unformatted_message) if field_name]
        formatter_dictionary:dict = { k:formatvalues[k] for k,v in required_fields if k in formatvalues }

        return unformatted_message.format(**formatter_dictionary)


def BasicExceptionDetails(exception:Exception) -> str:
    """Used throughout the program to render basic exception information from the given exception.

    Function Parameters
    --------------------
    exception:Exception
        The exception whose typename and message should be included in the rendered string.

    Return Value(s)
    --------------------
    1.) str:
        The string containing the basic exception details render.
    """
    return "Basic exception details: {0}:{1}".format(type(exception), str(exception))

def ClearConsole(newlines:int=100) -> None:
    """A dirty yet effective cross-platform function to clear the console.

    Attempts to call the respective clear function of the OS as identified
    by the os.name() function. If the OS cannot be determined, then newlines
    are dumped to the console instead.

    Function Parameters
    --------------------
    newlines:int = 100
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


def ApplyPkcs7(data:bytes, multiple:int=16) -> bytes:
    """Applies Pkcs7 padding to 'data' around a given multiple.

    Function Parameters
    --------------------
    data:bytes
        A sequence of bytes that should be padded.

    multiple:int
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

    delta:int = multiple - (len(data) % multiple)

    if delta != multiple:
        return data + bytes([delta] * delta)
    else:
        return data

def StripPkcs7(data:bytes) -> bytes:
    """Strips Pkcs7 padding from 'data' if present.

    Function Parameters
    --------------------
    data:bytes
        The sequence of bytes that should be depadded.

    Return Value(s)
    --------------------
    1.) bytes:
        The data that has been stripped of Pkcs7 padding. If the data did not
        contain Pkcs7 padding, then the original data is returned unmodified.
    """

    if not isinstance(data, bytes):
        raise TypeError("Argument 'data' is of an invalid type; expected {0} got {1}".format(bytes, type(data)))

    delta:int = data[-1]

    if len(data) >= delta and all(map(lambda byte: byte == delta, data[-delta:])):
        return data[0:-delta]

    return data


def ExtendedAesCbcEncrypt(data:bytes, key:bytes, keylen:int=32, keyalg:str="sha256", ivmask_len:int=AES.block_size) -> bytes:
    """Wrapper around PyCryptoDome's AES-CBC encryption function with extended functionality.

    This wrapper function utilizes an IV mask in order to mitigate the problem of having
    to store and transfer IV's. An IV mask is a random sequence of bytes that must be of
    length 16 or greater (AES.block_size) which is added to the input data before being
    encrypted, and removed from the output data after decryption. This ensures that the
    actual input data will not be XOR'd with the random IV, as the IV will only affect
    the first 16 bytes which have been made random, and therefore the IV is not needed
    and decryption is allowed to fail for the first 16 bytes because the data decrypted
    is inconsequential, and can later stripped from the output.

    If IV mask has been disabled by setting ivmask_len to 0, then the first 16 bytes of
    the encryption key's hash is used as the IV instead, in order to support legacy vault
    formats where IV masks were not implemented, and the encryption key's hash was used.
    This should only be used in cases of compatibility, and is not actively recommended,
    due to vulnurabilities created using this method.

    This function also utilizes a hash algorithm to transform an any-length sequence of
    bytes into a fixed-length encryption key, allowing for encryption keys to be of any
    length, rather than conforming to the key length mode of the AES-CBC (16, 24, 32)

    Function Parameters
    --------------------
    data:bytes
        The unencrypted data targeted for AES-CBC encryption.

    key:bytes
        A sequence of bytes whose hash will be used as the encryption key.

    keylen:int = 32
        The AES-CBC length mode to be used for encryption. This value must be
        one of the following: 16, 24, 32 - in respect to AES128, AES196, AES256

    keyalg:str = "sha256"
        The hashlib algorithm name that will be used to digest the 'key' argument.
        The value must be present within hashlib.algorithms_available

    ivmask_len:int = AES.block_size
        The length of the IV mask to apply to the input data before encryption.
        This value must be greater or equal to 16 to enable IV mask, or 0 to disable.

    Return Value(s)
    --------------------
    1.) bytes:
        The input data that has been encrypted using AES-CBC.

    Possible Exceptions
    --------------------
    - InvalidArgumentTypeError
        A provided argument had an incorrect type.

    - InvalidAesKeylenError
        The 'keylen' argument had a value which wasn't in (16, 24, 32)

    - InvalidHashlibAlgError
        The 'keyalg' argument had a value which wasn't present in hashlib.algorithms_available

    - IvMaskLengthError
        The value of 'ivmask_len' was less than 16 and greater than 0.

    - DigestLengthError
        The digest output length of the 'keyalg' algorithm is less than what is required by 'keylen'

    - InvalidEncryptionInputError
        Data passed to PyCryptoDome's encrypt function was rejected, most likely as a result of the data
        having been invalidly padded, and whose length does not follow a multiple of AES.block_size
    """

    if not isinstance(data, bytes):
        raise InvalidArgumentTypeError.auto("data", bytes, type(data))

    if not isinstance(key, bytes):
        raise InvalidArgumentTypeError.auto("key", bytes, type(key))

    if not isinstance(keylen, int):
        raise InvalidArgumentTypeError.auto("keylen", int, type(keylen))

    if not isinstance(keyalg, str):
        raise InvalidArgumentTypeError.auto("keyalg", str, type(keyalg))

    if not isinstance(ivmask_len, int):
        raise InvalidArgumentTypeError.auto("ivmask_len", int, type(ivmask_len))

    if keylen not in (16, 24, 32):
        raise InvalidAesKeylenError.auto(keylen)

    if keyalg not in hashlib.algorithms_available:
        raise InvalidHashlibAlgError.auto(keyalg)

    if ivmask_len != 0 and ivmask_len < 16:
        raise IvMaskLengthError.auto(ivmask_len)

    key_digest:bytes = hashlib.new(keyalg, key).digest()

    if len(key_digest) < keylen:
        raise DigestLengthError.auto(keyalg, len(key_digest), keylen)

    # Generate an IV if ivmask is being used, otherwise use the key's digest.
    iv:bytes = Random.get_random_bytes(AES.block_size) if ivmask_len else key_digest

    # Create a new PyCryptoDome AES-CBC cipher object, used for encryption.
    cipher = AES.new(key_digest[:keylen], AES.MODE_CBC, iv[:AES.block_size])

    # Introduce IV mask to data.
    data = Random.get_random_bytes(ivmask_len) + data

    # Apply Pkcs7 padding to data.
    data = ApplyPkcs7(data, 16)

    # Perform AES-CBC encryption on data.
    try:
        data = cipher.encrypt(data)
    except ValueError as e:
        raise InvalidEncryptionInputError.auto() from e

    return data

def ExtendedAesCbcDecrypt(data:bytes, key:bytes, keylen:int=32, keyalg:str="sha256", ivmask_len:int=AES.block_size) -> bytes:
    """Wrapper around PyCryptoDome's AES-CBC decryption function with extended functionaity.

    This wrapper function utilizes an IV mask in order to mitigate the problem of having
    to store and transfer IV's. An IV mask is a random sequence of bytes that must be of
    length 16 or greater (AES.block_size) which is added to the input data before being
    encrypted, and removed from the output data after decryption. This ensures that the
    actual input data will not be XOR'd with the random IV, as the IV will only affect
    the first 16 bytes which have been made random, and therefore the IV is not needed
    and decryption is allowed to fail for the first 16 bytes because the data decrypted
    is inconsequential, and can later stripped from the output.

    If IV mask has been disabled by setting ivmask_len to 0, then the first 16 bytes of
    the encryption key's hash is used as the IV instead, in order to support legacy vault
    formats where IV masks were not implemented, and the encryption key's hash was used.
    This should only be used in cases of compatibility, and is not actively recommended,
    due to vulnurabilities created using this method.

    This function also utilizes a hash algorithm to transform an any-length sequence of
    bytes into a fixed-length encryption key, allowing for encryption keys to be of any
    length, rather than conforming to the key length mode of the AES-CBC (16, 24, 32)

    Function Parameters
    --------------------
    data:bytes
        The encrypted data targeted for AES-CBC decryption.

    key:bytes
        A sequence of bytes whose hash will be used as the decryption key.

    keylen:int = 32
        The AES-CBC length mode to be used for decryption. This value must be
        one of the following: 16, 24, 32 - in respect to AES128, AES196, AES256

    keyalg:str = "sha256"
        The hashlib algorithm name that will be used to digest the 'key' argument.
        The value must be present within hashlib.algorithms_available

    ivmask_len:int = AES.block_size
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

    - InvalidAesKeylenError
        The 'keylen' argument had a value which wasn't in (16, 24, 32)

    - InvalidHashlibAlgError
        The 'keyalg' argument had a value which wasn't present in hashlib.algorithms_available

    - IvMaskLengthError
        The value of 'ivmask_len' was less than 16 and greater than 0.

    - DigestLengthError
        The digest output length of the 'keyalg' algorithm is less than what is required by 'keylen'

    - InvalidDecryptionInputError
        Data passed to PyCryptoDome's decrypt function was rejected, most likely as a result of
        attempting to decrypt non-encrypted data whose length isn't a multiple of AES.block_size
    """

    if not isinstance(data, bytes):
        raise InvalidArgumentTypeError.auto("data", bytes, type(data))

    if not isinstance(key, bytes):
        raise InvalidArgumentTypeError.auto("key", bytes, type(key))

    if not isinstance(keylen, int):
        raise InvalidArgumentTypeError.auto("keylen", int, type(keylen))

    if not isinstance(keyalg, str):
        raise InvalidArgumentTypeError.auto("keyalg", str, type(keyalg))

    if not isinstance(ivmask_len, int):
        raise InvalidArgumentTypeError.auto("ivmask_len", int, type(ivmask_len))

    if keylen not in (16, 24, 32):
        raise InvalidAesKeylenError.auto(keyalg)

    if keyalg not in hashlib.algorithms_available:
        raise InvalidHashlibAlgError.auto(keyalg)

    if ivmask_len != 0 and ivmask_len < 16:
        raise IvMaskLengthError.auto(ivmask_len)

    key_digest:bytes = hashlib.new(keyalg, key).digest()

    if len(key_digest) < keylen:
        raise DigestLengthError.auto(keyalg, len(key_digest), keylen)

    # Generate an IV if an ivmask is being used, otherwise use the key's digest.
    iv:bytes = Random.get_random_bytes(AES.block_size) if ivmask_len else key_digest

    # Creates a new PyCryptoDome AES-CBC cipher object, used for decryption.
    cipher = AES.new(key_digest[:keylen], AES.MODE_CBC, iv[:AES.block_size])

    # Perform AES-CBC decryption on data.
    try:
        data = cipher.decrypt(data)
    except ValueError as e:
        raise InvalidDecryptionInputError.auto() from e

    # Strip Pkcs7 padding from data.
    data = StripPkcs7(data)

    # Strip the IV mask from the data (doesn't break if there is no IV mask as ivmask_len becomes 0)
    data = data[ivmask_len:]

    return data


def ReadVault(filepath:str, key:bytes, keylen:int=32, keyalg:str="sha256", ivmask_len:int=AES.block_size) -> dict:
    """Loads a specified vault file into a dictionary, using the given decryption parameters.

    This function is an abstraction of the following series of steps:
    Validate Arguments -> Read File -> Aes Decrypt -> UTF-8 Decode -> Json Parse -> Return Dictionary

    Function Parameters
    --------------------
    filepath:str
        The path pointing to the vault file that should be loaded.

    key:bytes
        The encryption key argument that will be provided to ExtendedAesCbcDecrypt

    keylen:int = 32
        The AES-CBC key length mode argument that will be provided to ExtendedAesCbcDecrypt

    keyalg:str = "sha256"
        The hashlib algorithm argument that will be provided to ExtendedAesCbcDecrypt

    ivmask_len:int = AES.block_size
        The IV mask length argument that will be provided to ExtendedAesCbcDecrypt

    Return Value(s)
    --------------------
    1.) dict:
        The loaded credentials dictionary contained within the vault file.

    Possible Exceptions
    --------------------
    i.) Any exceptions raised by ExtendedAesCbcDecrypt, check function docstring for more info.

    - InvalidArgumentValueError
        As a result of an argument (namely the 'key' argument) having a problematic value.
        Re-raised from UnicodeEncodeError if raised by str.encode()

    - InvalidArgumentTypeError
        As a result of an argument being of an invalid type, applies to all arguments.

    - FileNotFoundError
        As a result of 'filepath' pointing to an invalid location.

    - PostDecryptionUnicodeDecodeError
        As a result of the decryption output being non-mappable by Unicode, indicating a failed decryption.
        Re-raised from UnicodeDecodeError if raised by bytes.decode()

    - PostDecryptionJsonLoadError
        As a result of the decryption output being unloadable by JSON, indicating a failed decryption.
        Re-raised from json.JSONDecodeError if raised by json.loads()
    """

    # Argument Validation Step
    # --------------------------------------------------
    if isinstance(key, str):
        try:
            key = key.encode()
        except UnicodeEncodeError as e:
            exception_message:str = "Argument 'key' is a string which contains one or more characters that cannot be encoded into a byte sequence."
            raise InvalidArgumentValueError(exception_message) from e

    if not isinstance(filepath, str):
        raise InvalidArgumentTypeError.auto("filepath", str, type(filepath))

    if not os.path.isfile(filepath):
        raise FileNotFoundError("Cannot read vault because the file '{0}' cannot be found.".format(filepath))

    if key is not None:
        if not isinstance(key, bytes):
            raise InvalidArgumentTypeError.auto("key", bytes, type(key))

        if not isinstance(keylen, int):
            raise InvalidArgumentTypeError.auto("keylen", int, type(keylen))

        if not isinstance(keyalg, str):
            raise InvalidArgumentTypeError.auto("keyalg", str, type(keyalg))

        if not isinstance(ivmask_len, int):
            raise InvalidArgumentTypeError.auto("ivmask_len", int, type(ivmask_len))

    # Read From File
    # --------------------------------------------------
    with open(filepath, "rb") as io:
        file_bytes:bytes = io.read()
        io.close()

    # Optional Decryption Step
    # --------------------------------------------------
    if key is not None:
        file_bytes = ExtendedAesCbcDecrypt(file_bytes, key, keylen, keyalg, ivmask_len)

    # UTF-8 Decoding Step
    # --------------------------------------------------
    try:
        credentials_json:str = file_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise PostDecryptionUnicodeDecodeError.auto() from e

    # JSON Loading Step
    # --------------------------------------------------
    try:
        credentials:dict = json.loads(credentials_json)
    except json.JSONDecodeError as e:
        raise PostDecryptionJsonLoadError.auto() from e

    return credentials

def WriteVault(credentials:dict, filepath:str, key:bytes, keylen:int=32, keyalg:str="sha256", ivmask_len:int=AES.block_size, overwrite:bool=False) -> (int, str):
    """Writes the specified credentials dictionary into a vault file using the given encryption parameters.

    This function is an abstraction of the following series of steps:
    Validate Arguments -> Json Serialize Credentials -> UTF-8 Encode -> Aes Encrypt -> Write To File

    Function Parameters
    --------------------
    credentials:dict
        The dictionary containing the credentials that sould be written to the vault file.

    filepath:str
        The path pointing to the vault file that should be written to.

    key:bytes
        The encryption key argument that will be provided to ExtendedAesCbcDecrypt

    keylen:int = 32
        The AES-CBC key length mode argument that will be provided to ExtendedAesCbcDecrypt

    keyalg:str = "sha256"
        The hashlib algorithm argument that will be provided to ExtendedAesCbcDecrypt

    ivmask_len:int = AES.block_size
        The IV mask length argument that will be provided to ExtendedAesCbcDecrypt

    overwrite:bool = False
        Specifies whether or not the function has permission to overwrite an existing file.
        If an attempt is made to overwrite when this is False, a FileExistsError is raised.

    Return Value(s)
    --------------------
    1.) int:
        The amount of bytes that have been written to the vault file.

    2.) str:
        The SHA256 digest of the data that was written to the vault file.

    Possible Exceptions
    --------------------------------------------------
    i.) Any exceptions raised by ExtendedAesCbcEncrypt, check function docstring for more info.

    - InvalidArgumentValueError
        As a result of an argument (namely the 'key' argument) having a problematic value.
        Re-raised from UnicodeEncodeError if raised by str.encode()

    - InvalidArgumentTypeError
        As a result of an argument being of an invalid type, applies to all arguments.

    - FileExistsError
        As a result of the 'filepath' argument pointing to an existing file while the 'overwrite' argument is set to False.

    - PreEncryptionJsonDumpError
        As a result of the 'credentials' dictionary containing a value whose type is not JSON serializable.
        Re-raised from TypeError if raised by json.dumps()

    - PreEncryptionUnicodeEncodeError
        As a result of json.dumps() giving an output containing a character that cannot be mapped to a byte using Unicode/UTF-8.
        This is a very rare error, but is not impossible as characters could be stored in Python memory using a different charset
        than the one being used to encode the characters into bytes, still, this remains highly unlikely.
        Re-raised from UnicodeEncodeError if raised by str.encode()
    """

    # Argument Validation Step
    # --------------------------------------------------
    if isinstance(key, str):
        try:
            key = key.encode()
        except UnicodeEncodeError as e:
            exception_message:str = "Argument 'key' is a string which contains one or more characters that cannot be encoded into a byte sequence."
            raise InvalidArgumentValueError(exception_message) from e

    if not isinstance(filepath, str):
        raise InvalidArgumentTypeError.auto("filepath", str, type(filepath))

    if os.path.isfile(filepath) and not overwrite:
        raise FileExistsError("File at '{0}' already exists, will not overwrite when overwrite=False")

    if not isinstance(overwrite, bool):
        raise InvalidArgumentTypeError.auto("overwrite", bool, type(overwrite))

    if key is not None:
        if not isinstance(key, bytes):
            raise InvalidArgumentTypeError.auto("key", bytes, type(key))

        if not isinstance(keylen, int):
            raise InvalidArgumentTypeError.auto("keylen", int, type(keylen))

        if not isinstance(keyalg, str):
            raise InvalidArgumentTypeError.auto("keyalg", str, type(keyalg))

        if not isinstance(ivmask_len, int):
            raise InvalidArgumentTypeError.auto("ivmask_len", int, type(ivmask_len))

    # JSON Dumping Step
    # --------------------------------------------------
    try:
        file_json:str = json.dumps(credentials)
    except TypeError as e:
        exception_message:str = "Argument 'credentials' contains a key or value that cannot be serialized into JSON."
        raise PreEncryptionJsonDumpError.auto() from e

    # UTF-8 Encoding Step
    # --------------------------------------------------
    try:
        file_bytes:bytes = file_json.encode()
    except UnicodeEncodeError as e:
        raise PreEncryptionUnicodeEncodeError.auto() from e

    # Optional Encryption Step
    # --------------------------------------------------
    if key is not None:
        file_bytes = ExtendedAesCbcEncrypt(file_bytes, key, keylen, keyalg, ivmask_len)

    # Write To File
    # --------------------------------------------------
    with open(filepath, "wb+") as io:
        byteswritten:int = io.write(file_bytes)
        io.close()

    return byteswritten, hashlib.sha256(file_bytes).hexdigest()


def RenderCredentialsPage(credentials:dict, page_number:int=0, page_rows:int=10, index_selection:int=None, subindex_selection:int=None) -> (str, str, str):
    """Renders the primary credentials browser, used for navigation and accessing of credentials.

    This is used primary to display the credentials, but is also used to select specific
    accounts and account entries by providing an index and subindex relative to what is
    being displayed on the render, and the matching dictionary keys will be returned.

    Function Parameters
    --------------------
    credentials:dict
        The credentials dictionary that should be rendered.

    page_number:int = 0
        The page number that should be displayed, relative to page_rows.

    page_rows:int = 10
        The amount of rows to display per page. Increasing this value will
        consequently decrease the amount of pages.

    index_selection:int = None
        The index of the account that should be selected in the render.
        Having this value set to None clears the selection.

    subindex_selection:int = None
        The index of the account's entry that should be selected in the render.

    Return Value(s)
    --------------------
    1.) str:
        The string that contains the rendered credentials page.

    2.) str:
        The name of the account key in the provided credentials dictionary which matches
        the account index that has been provided via index_selection and that is selected
        in the results of the render.

    3.) str:
        The name of the entry key in the provided credentials dictionary which matches
        the entry inddex that has been provided with subindex_selection and that is selected
        in the results of the render.
    """

    rendered_lines_buffer:list = []

    index_map:list = list(credentials) # Turning a dict into a list only stores the dict's keys, and not its values.

    page_start_index:int = page_number * page_rows
    page_end_index:int = (len(index_map) if page_start_index + page_rows >= len(index_map) else page_start_index + page_rows)

    key_selection, subkey_selection = None, None

    if page_start_index < len(index_map):
        page_keys:list = index_map[page_start_index:page_end_index]

        for index in range(page_start_index, page_end_index):
            key = index_map[index]

            if index == index_selection:
                subkeys:list = list(credentials[key])
                key_selection = key

                rendered_lines_buffer.append("|-> ({0}) {1}".format(index, key))

                for subindex, subkey in enumerate(subkeys):
                    if subindex == subindex_selection:
                        subkey_selection = subkey
                        rendered_lines_buffer.append("|----> ({0}-{1}) >> {2}={3}".format(index, subindex, subkey, credentials[key][subkey]))
                    else:
                        rendered_lines_buffer.append("|     ({0}-{1}) >> {2}={3}".format(index, subindex, subkey, credentials[key][subkey]))
            else:
                rendered_lines_buffer.append("|    ({0}) {1}".format(index, key))

    return "\n".join(rendered_lines_buffer), key_selection, subkey_selection

def RenderDictDiff(old_values:dict, new_values:dict) -> str:
    """Renders a diff between two dictionaries and returns the render as a string.

    Function Parameters
    --------------------
    old_values:dict
        The original dictionary that should be compared against.

    new_values:dict
        The modified dictionary that should be compared from.

    Return Value(s)
    --------------------
    1.) str:
        The string that has been rendered with the results of the diff.
    """

    render_lines_buffer:list = []

    for k,v in new_values.items():
        if k not in old_values:
            render_lines_buffer.append(" [+] {0}".format(k))

            for sk,sv in v.items():
                render_lines_buffer.append(" [+] {0}/{1}".format(k, sk))
        else:
             for sk,sv in v.items():
                 if sk not in old_values[k]:
                     render_lines_buffer.append(" [+] {0}/{1}".format(k, sk))
                 else:
                     if sv != old_values[k][sk]:
                         render_lines_buffer.append(" [~] {0}/{1}".format(k, sk))

    for k,v in old_values.items():
        if k not in new_values:
            render_lines_buffer.append(" [-] {0}".format(k))

            for sk,sv in v.items():
                render_lines_buffer.append(" [-] {0}/{1}".format(k, sk))
        else:
            for sk,sv in v.items():
                if sk not in new_values[k]:
                    render_lines_buffer.append(" [-] {0}/{1}".format(k, sk))

    return "\n".join(render_lines_buffer)

def GenerateRandomPassword(sequences:list, size:int) -> str:
    """ Generates a random password of a given size using the provided character classes.

    This random password generator places emphasis on every character class having an equal
    chance of appearing in the output, so character classes with more characters, e.g. the
    alphabet containing more characters than digits 0-9, will appear with same frequency.

    Function Parameters
    --------------------
    sequences:list
        A list of character classes to be used when generating the password.
        Character classes are strings that can be one of the following
         : alpha, alphalower, alphaupper, numerical, special, extra
        If a string is provided that isn't one of these character classes,
        the string's characters will be interpreted as the character class.

    size:int
        The length of the password.

    Return Value(s)
    --------------------
    1.) str:
        The string containing the randomly generated password.

    Possible Exceptions
    --------------------
    InvalidArgumentTypeError
        As a result of a provided argument having an invalid type.
    """

    if not isinstance(sequences, list):
        raise InvalidArgumentTypeError.auto("sequences", list, type(sequences))

    if not isinstance(size, int):
        raise InvalidArgumentTypeError.auto("size", int, type(size))

    master_sequence:list = []

    none_in = lambda source, target: all(map(lambda e: e not in target, source))

    for sequence in sequences:
        if sequence == "alpha" and none_in((ascii_letters, ascii_lowercase, ascii_uppercase), master_sequence):
            master_sequence.append(ascii_letters)

        elif sequence == "alphalower" and none_in((ascii_lowercase, ascii_uppercase, ascii_letters), master_sequence):
            master_sequence.append(ascii_lowercase)

        elif sequence == "alphaupper" and none_in((ascii_lowercase, ascii_uppercase, ascii_letters), master_sequence):
            master_sequence.append(ascii_uppercase)

        elif sequence == "numerical" and ascii_digits not in master_sequence:
            master_sequence.append(ascii_digits)

        elif sequence == "special" and none_in((ascii_special, "!#$%&*+-=?@^_|"), master_sequence):
            if "extra" in sequences:
                master_sequence.append(ascii_special)
            else:
                master_sequence.append("!#$%&*+-=?@^_|")

    return "".join(map(lambda _: random.choice(random.choice(master_sequence)), range(size)))

def IntegrityCheck(filepath:str, hash_in_ram:str) -> bool:
    """ Performs a SHA256 integrity check between the provided hash and the hash of the vault file.

    Function Parameters
    --------------------
    filepath:str
        The path to the file that the integrity check should be performed against.

    hash_in_ram:str
        The SHA256 hash which the file is expected to have.

    Return Value(s)
    --------------------
    1.) bool:
        Bool that indicates if the file passed the integrity check or not.
    """

    with open(filepath, "rb") as io:
        data:bytes = io.read()
        io.close()

    hash_on_disk:str = hashlib.sha256(data).hexdigest()

    print("-"*50)
    print("RAM  HASH (sha256):", hash_in_ram)
    print("DISK HASH (sha256):", hash_on_disk)
    print("-"*50)

    if hash_in_ram == hash_on_disk:
        print("Integrity Check Passed\n")
        return True
    else:
        print("INTEGRITY CHECK FAILED !!")
        print("There is a conflict between the data in memory and the data on the disk, the data was not properly saved!")
        print("To preserve the data stored in memory, try one of the following recommendations..",end="\n\n")
        print("1.) Use the write command to write the file to a new location, rather than overwriting the existing vault.")
        print("2.) Use the dumpjson command to dump the unencrypted JSON data into your clipboard, store it in a file, and use the --insecure flag to load it and then re-encrypt it using make-secure.")
        return False


if __name__ == "__main__":
    argp = argparse.ArgumentParser(description = "Python CLI implementation of (L)ocally(S)tored(P)assword(M)anager")


    argp.add_argument(
        "--file", "-f",
        action="store",
        nargs="?",
        required=True,
        type=lambda argument: os.path.abspath(argument),
        help="A path pointing to the vault file that should be created or loaded.",
        dest="vaultpath",
    )


    argp.add_argument(
        "--keylen", "-kl",
        action="store",
        nargs="?",
        default=32,
        type=int,
        choices=[16, 24, 32],
        required=False,
        help="The AES-CBC key length to use for encryption/decryption; 128=>16, 196=>24, 256=>32",
        dest="keylen"
    )


    argp.add_argument(
        "--keyalg", "-ka",
        action="store",
        nargs="?",
        default="sha256",
        choices=hashlib.algorithms_available,
        required=False,
        help="The name of the hashlib algorithm to be applied onto the password from which --keylen amount of bytes will be used as the AES-CBC key.",
        dest="keyalg"
    )


    argp.add_argument(
        "--ivmask", "-ivm",
        action="store",
        nargs="?",
        default=16,
        type=int,
        required=False,
        help="The amount of random bytes that should be added or stripped from the start of the encryption/decryption output in order to mask the IV; should be 16 at the very least (AES block size)",
        dest="ivmask_len"
    )


    argp.add_argument(
        "--insecure", "-is",
        action="store_true",
        default=False,
        required=False,
        help="When present, this flag makes the program treat the file pointed to by --file as an unencrypted insecure vault, decryption will not be attempted. This also affects the encryption of newly created vaults.",
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


    if not os.path.isfile(pargs.vaultpath):
        print("The vault file '{0}' doesn't exist yet, create a new vault file at that location?".format(pargs.vaultpath))

        if input("Y/N >> ").lower() in ("y", "yes"):
            password:str = getpass.getpass() if not pargs.insecure_mode else None

            try:
                wrote = WriteVault({}, pargs.vaultpath, password, keylen=pargs.keylen, keyalg=pargs.keyalg, ivmask_len=pargs.ivmask_len)
            except Exception as e:
                print("-"*50)
                print("Failure when attempting to write vault to location '{0}'".format(pargs.vaultpath))
                print(ExceptionMessageResolver.Resolve("WriteVault", type(e), {**pargs.__dict__, **locals()}))
                print(BasicExceptionDetails(e))
                print("-"*50)

                if pargs.debug_mode:
                    raise e
                else:
                    print("Use the --debug flag to view the exception traceback.")
                    raise SystemExit

            print("Wrote", wrote, "bytes to", pargs.vaultpath, end="\n\n")

        else:
            raise SystemExit

    if not os.path.isfile(pargs.vaultpath):
        print("Cannot find vault file '{0}'".format(pargs.vaultpath))
        raise SystemExit

    print("Loading vault..", pargs.vaultpath)

    password = None

    if not pargs.insecure_mode:
        password = getpass.getpass()

    try:
        credentials:dict = ReadVault(pargs.vaultpath, password, keylen=pargs.keylen, keyalg=pargs.keyalg, ivmask_len=pargs.ivmask_len)
    except Exception as e:
        print("-"*50)
        print("Failure when attempting to read from vault at location '{0}'".format(pargs.vaultpath))
        print(ExceptionMessageResolver.Resolve("ReadVault", type(e), {**pargs.__dict__, **locals()}))
        print(BasicExceptionDetails(e))
        print("-"*50)

        if pargs.debug_mode:
            raise e
        else:
            print("Use the --debug flag to view the exception traceback.")
            raise SystemExit

    # A deep copy of the credentials dict, used to keep track of the
    # original values before any modificatiosn were made. The diff
    # command uses this, as well as the restore command. This value
    # is re-assigned when using the save command to save changes.
    credentials_backup:dict = copy.deepcopy(credentials)

    # Stores the filtered version of the credentials dict when using
    # the filter command to filter accounts by search terms.
    filtered_credentials:dict = None

    # Stores the list of search terms used to filter the credentials
    # dictionary with. The matching results get stored into the above
    # filtered_credentials dictionary. If this value is None, that is
    # interpreted as not having any search filters active. This is set
    # to None by the clearfilter command.
    render_search_filter:list = None

    # Tracks the current page number that should be rendered. Changed
    # whenever the page is changed using the page switching command.
    render_pagenumber:int = 0

    # Determines how many rows of accounts should be rendered per page,
    # and therefore also determines the amount of pages in total, as
    # whenever a page is full, the remaining rows overflow to the next.
    render_pagerows:int = 20

    # Keeps track of the selected account's index that was selected using
    # the select command. When this value is None, that is interpreted as
    # nothing being currently selected. This is set to None when using the
    # clear selection command.
    render_selected_index:int = None

    # Keeps track of the selected entry's index that was selected using
    # the select command. When this value is None, that is interpreted as
    # nothing being currently selected. This is set to None when using the
    # clear selection command.
    render_selected_subindex:int = None

    # Keeps track of the vault's security state as changed by make-secure
    # or make-insecure. By default this is set to the resulting value of
    # the --insecure command line argument, which by default is False.
    vault_insecure_mode:bool = pargs.insecure_mode

    # Primary Command Processing And Rendering Loop
    # ----------------------------------------------------------------------------------------------------
    while True:
        os.system("cls")

        print("-" * 50)
        print("| {0}: keyalg {1}, keylen {2}, ivmask {3}".format("Insecure" if vault_insecure_mode else "Secure", pargs.keylen, pargs.keyalg, pargs.ivmask_len))
        print("-" * 50)

        if isinstance(render_search_filter, list):
            filtered_credentials = { k:v for (k,v) in credentials.items() if any(map(lambda f: f.lower() in k.lower(), render_search_filter)) }
            rendered_credentials, selected_key, selected_subkey = RenderCredentialsPage(filtered_credentials, render_pagenumber, render_pagerows, render_selected_index, render_selected_subindex)
            print(rendered_credentials)
        else:
            filtered_credentials = None
            rendered_credentials, selected_key, selected_subkey = RenderCredentialsPage(credentials, render_pagenumber, render_pagerows, render_selected_index, render_selected_subindex)
            print(rendered_credentials)

        print("-" * 50)
        print("| Page {0} / {1}".format(render_pagenumber, (len(filtered_credentials) if filtered_credentials else len(credentials)) // render_pagerows))
        print("-" * 50)

        if filtered_credentials:
            print("Filters: any({0})".format(render_search_filter))
            print("-"*50)

        command = input("Command: ")
        command_split = command.split(" ")

        for index, cmd in enumerate(command_split):
            next_cmd = command_split[index + 1] if index + 1 < len(command_split) else None

            # Page Selection
            # --------------------------------------------------
            if cmd.isdigit() and len(command_split) == 1:
                render_pagenumber = int(cmd)

            # Show Command Reference Text
            # --------------------------------------------------
            if cmd in ("help", "?", "what"):
                print(COMMAND_REFERENCE_TEXT)
                input("Press enter to continue...")

            # Restore Vault Backup / Revert Changes
            # --------------------------------------------------
            elif cmd in ("restore", "revert"):
                print("-"*50)
                print(RenderDictDiff(credentials_backup, credentials))
                print("-"*50)
                print("You are about to revert these changes in memory, any modifications you made will be lost unless saved.")
                print("Confirm that you want to revert these changes?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                credentials = copy.deepcopy(credentials_backup)
                print("Changes have been reverted.")
                input("Press enter to continue..")

            # JSON Vault Dump Command
            # --------------------------------------------------
            elif cmd in ("dumpjson",):
                print("Are you sure you want to dump your entire vault as unencrypted JSON into your terminal?")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                print("-"*50)
                print(json.dumps(credentials, indent=4))
                print("-"*50)

                input("Press enter to continue..")

            # Convert Unencrypted Vault To Encrypted Vault
            # --------------------------------------------------
            elif cmd in ("make-secure",):
                if not vault_insecure_mode:
                    print("The vault is already set to secure mode, use this command to convert an insecure vault to a secure vault.")
                    input("Press enter to continue..")
                    continue

                print("You are about to convert your vault from an insecure plaintext vault into an secure AES-CBC encrypted vault.")
                print("Until you save the vault using the save command, this will not affect the vault on your disk.")
                print("Confirm that you want to switch the vault mode from insecure to secure?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                new_password:str = getpass.getpass("New Password: ")
                again:str = getpass.getpass("Again: ")

                if new_password != again:
                    print("Cancelling operation, the typed passwords do not match.")
                    continue

                password = new_password
                vault_insecure_mode = False

                print("Vault mode has been changed to secure.")
                input("Press enter to continue..")

            # Convert Encrypted Vault To Unenrypted Vault
            # --------------------------------------------------
            elif cmd in ("make-insecure",):
                if vault_insecure_mode:
                    print("The vault is already set to insecure mode, use this command to convert a secure vault to an insecure vault.")
                    input("Press enter to continue..")
                    continue

                print("You are about to convert your vault from a secure AES-CBC encrypted vault into an insecure plaintext vault.")
                print("Until you save the vault using the save command, this will not affect the vault on your disk.")
                print("Confirm that you want to switch the vault mode from secure to insecure?", end="\n\n")

                if input("Y/N > ").lower() not in ("yes", "y"):
                    continue

                reentered_password:str = getpass.getpass("Re-enter Password: ")

                if reentered_password != password:
                    print("Cancelling operation, re-entered password does not match the original password used to decrypt the vault.")
                    input("Press enter to continue..")
                    continue

                password = None
                vault_insecure_mode = True

                print("Vault mode has been changed to insecure.")
                input("Press enter to continue..")

            # Save Vault Changes
            # --------------------------------------------------
            elif cmd in ("save",):
                print("-"*50)
                print(RenderDictDiff(credentials_backup, credentials))
                print("-"*50)
                print("Confirm Diff Changes For Vault '{0}'".format(pargs.vaultpath))

                if input("Y/N > ").lower() not in ("y", "yes"):
                    continue

                if not vault_insecure_mode:
                    print("Re-enter Your Password")
                    reentered_password:str = getpass.getpass()

                    if reentered_password != password:
                        print("The entered password doesn't match the password used to decrypt the vault.")
                        print("To change passwords, use write instead of save, and select a new location.")
                        input("Press enter to continue..")
                        continue

                try:
                    wrote, hash_in_ram = WriteVault(credentials, pargs.vaultpath, password, keylen=pargs.keylen, keyalg=pargs.keyalg, ivmask_len=pargs.ivmask_len, overwrite=True)
                except Exception as e:
                    print("-"*50)
                    print("Failure when attempting to write vault to location '{0}'".format(pargs.vaultpath))
                    print(ExceptionMessageResolver.Resolve("WriteVault", type(e), {**pargs.__dict__, **locals()}))
                    print(BasicExceptionDetails(e))
                    print("-"*50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")
                        input("Press enter to continue..")
                        continue

                print("\nWrote {0} bytes to '{1}'".format(wrote, pargs.vaultpath))

                try:
                    if IntegrityCheck(pargs.vaultpath, hash_in_ram):
                        credentials_backup = copy.deepcopy(credentials)
                except Exception as e:
                    print("-"*50)
                    print("Failure when attempting to re-read contents of vault file for the purposes of checking its integrity '{0}'".format(pargs.vaultpath))
                    print(ExceptionMessageResolver.Resolve("IntegrityCheck", type(e), {**pargs.__dict__, **locals()}))
                    print(BasicExceptionDetails(e))
                    print("-"*50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")
                        input("Press enter to continue..")
                        continue

                input("Press enter to continue..")

            # Write Vault To File
            # --------------------------------------------------
            elif cmd in ("write",):
                print("-"*50)
                new_path:str = input("File Path >> ")
                print("-"*50)

                if os.path.isfile(new_path):
                    print("Cannot comply, a file with that name already exists. To save your changes, use save.")
                    input("Press enter to continue..")
                    continue

                print("Confirm filepath '{0}'".format(os.path.abspath(new_path)))

                if input("Y/N > ").lower() not in ("y", "yes"):
                    continue

                new_password = None

                if not vault_insecure_mode:
                    new_password:str = getpass.getpass("New Password: ")
                    password_again:str = getpass.getpass("Again: ")

                    if new_password != password_again:
                        print("Passwords do not match, try again")
                        input("Press enter to continue..")
                        continue

                try:
                    wrote, hash_in_ram = WriteVault(credentials, os.path.abspath(new_path), new_password, keylen=pargs.keylen, keyalg=pargs.keyalg, ivmask_len=pargs.ivmask_len, overwrite=False)
                except Exception as e:
                    print("-"*50)
                    print("Failure when attempting to write vault to location '{0}'".format(pargs.vaultpath))
                    print(ExceptionMessageResolver.Resolve("WriteVault", type(e), {**pargs.__dict__, **locals()}))
                    print(BasicExceptionDetails(e))
                    print("-"*50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")
                        input("Press enter to continue..")
                        continue

                print("\nWrote {0} bytes to '{1}'".format(wrote, os.path.abspath(new_path)))

                try:
                    if IntegrityCheck(os.path.abspath(new_path), hash_in_ram):
                        credentials_backup = copy.deepcopy(credentials)
                except Exception as e:
                    print("-"*50)
                    print("Failure when attempting to re-read contents of vault file for the purposes of checking its integrity '{0}'".format(pargs.vaultpath))
                    print(ExceptionMessageResolver.Resolve("IntegrityCheck", type(e), {**pargs.__dict__, **locals()}))
                    print(BasicExceptionDetails(e))
                    print("-"*50)

                    if pargs.debug_mode:
                        print(traceback.format_exc())
                    else:
                        print("Use the --debug flag to view the exception traceback.")
                        input("Press enter to continue..")
                        continue

                input("Press enter to continue..")

            # Exit Program
            # --------------------------------------------------
            elif cmd in ("exit", "quit"):
                raise SystemExit

            # Clear Selection
            # --------------------------------------------------
            elif cmd in ("cs", "clearsel", "clearselection"):
                render_selected_index = None
                render_selected_subindex = None

            # Clear Search Filter
            # --------------------------------------------------
            elif cmd in ("cf", "clearfiltr"):
                render_search_filter = None

            # Diff / View Changes
            # --------------------------------------------------
            elif cmd in ("diff",) and len(command_split) == 1:
                print("-"*50)
                print(RenderDictDiff(credentials_backup, credentials))
                print("-"*50)
                input("Press enter to continue..")

            # Copy Selection To Clipboard
            # --------------------------------------------------
            elif cmd in ("cp", "copy"):
                if selected_key != None and selected_subkey != None:
                    pyperclip.copy(credentials[selected_key][selected_subkey])
                    print("Copied text!")
                    time.sleep(0.2)

            # Add Entry To Selected Account
            # --------------------------------------------------
            elif cmd in ("a", "add"):
                if selected_key != None:
                    print("Adding new key to {0}".format(selected_key))

                    newkv_key = input("Key: ")

                    if newkv_key in credentials[selected_key]:
                        print("Cannot comply, a key with that name under the same account already exists.")
                        input("Press enter to continue..")
                        continue

                    newkv_val = input("Value: ")

                    print("Confirm addition ({0}) += ({1}:{2})".format(selected_key, newkv_key, newkv_val))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        credentials[selected_key][newkv_key] = newkv_val
                else:
                    print("Cannot comply, an account needs to be selected first in order to add a new entry to it.")
                    input("Press enter to continue..")

            # Delete Selected Entry
            # --------------------------------------------------
            elif cmd in ("del", "delete"):
                if selected_key != None and selected_subkey != None:
                    print("Confirm deletion ({0} / {1})".format(selected_key, selected_subkey))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        del credentials[selected_key][selected_subkey]
                else:
                    print("Cannot comply, an entry needs to be selected before it can be deleted.")
                    input("Press enter to continue..")

            # Modify Selected Entry's Value
            # --------------------------------------------------
            elif cmd in ("mod", "modify"):
                if selected_key != None and selected_subkey != None:
                    print("Modifying ({0} / {1})".format(selected_key, selected_subkey))
                    newval = input("New Value: ")
                    print("Confirm modification ({0} / {1}) = {2}".format(selected_key, selected_subkey, newval))
                    confirmation:bool = input("Y/N > ").lower() in ("yes", "y")

                    if confirmation:
                        credentials[selected_key][selected_subkey] = newval
                else:
                    print("Cannot comply, an entry needs to be selected before its value can be modified.")
                    input("Press enter to continue..")

            # Add Account
            # --------------------------------------------------
            elif cmd in ("aac", "addacc"):
                account_name = input("Account Name: ")

                if account_name in credentials:
                    print("Cannot comply, an account with that name already exists.")
                    input("Press enter to continue..")
                    continue
                else:
                    print("Confirm account addition (vault) += ({0})".format(account_name))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        credentials[account_name] = {}

            # Delete Selected Account
            # --------------------------------------------------
            elif cmd in ("dac", "delacc"):
                if selected_key != None:
                    print("Confirm account deletion (vault) -= ({0})".format(selected_key))

                    if input("Y/N > ").lower() in ("y", "yes"):
                        del credentials[selected_key]
                else:
                    print("Cannot comply, no account has been selected.")
                    input("Press enter to continue..")

            # Commands that rely on follow-up arguments.
            # ----------------------------------------------------------------------------------------------------
            if next_cmd != None:

                # Account & Entry Selection
                # --------------------------------------------------
                if cmd in ("s", "select") and index == 0:
                    if next_cmd.isdigit():
                        render_selected_index = int(next_cmd)

                    elif "-" in next_cmd:
                        next_cmd_split = next_cmd.split("-")

                        if len(next_cmd_split) == 2 and all(map(lambda e: e.isdigit(), next_cmd_split)):
                            render_selected_index = int(next_cmd_split[0])
                            render_selected_subindex = int(next_cmd_split[1])

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
                        print("Cannot comply, an entry must first be selected before a random password can be inserted into it.")
                        input("Press enter to continue..")
                        continue

                    password_length:int = int(next_cmd)
                    random_password:str = GenerateRandomPassword(command_split[2:], password_length)
                    credentials[selected_key][selected_subkey] = random_password

                # Set Display Filter
                # --------------------------------------------------
                elif cmd in ("f", "filter") and index == 0:
                    render_search_filter = command_split[1:]

                # Change Rows Display Count
                # --------------------------------------------------
                elif cmd in ("pr", "rows") and index == 0:
                    if next_cmd.isdigit() and int(next_cmd) > 0:
                        render_pagerows = int(next_cmd)

                # Set Secspec Keyalg
                # --------------------------------------------------
                elif cmd in ("keyalg",) and index == 0:
                    if next_cmd in hashlib.algorithms_available:
                        pargs.keyalg = next_cmd
                    else:
                        print("Cannot comply, algorithm '{0}' is not available.".format(next_cmd))
                        print("Available algorithms: {0}".format(hashlib.algorithms_available))
                        input("Press enter to continue..")

                # Set Secspec Keylen
                # --------------------------------------------------
                elif cmd in ("keylen",) and index == 0:
                    if next_cmd in ("16", "24", "32"):
                        pargs.keylen = int(next_cmd)
                    else:
                        print("Cannot comply, '{0}' is not a valid AES key length, must be one of: [16, 24, 32] bytes ( = [128, 196, 256] bits)".format(next_cmd))
                        input("Press enter to continue..")

                # Set Secspec IvMask
                # --------------------------------------------------
                elif cmd in ("ivmask",) and index == 0:
                    if next_cmd.isdigit():
                        pargs.ivmask_len = int(next_cmd)
                    else:
                        print("Cannot comply, '{0}' is not a valid digit.".format(next_cmd))
                        input("Press enter to continue..")

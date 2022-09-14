# The Krypton Password Manager

Krypton is an open source command line password manager built in Python, intended for power users with a heavy emphasis on privacy. I created this password manager because I don't trust my credentials in the hands of company servers running proprietary code behind closed doors; I want complete control over my password manager, its security, and where the data ends up. I also find most password managers to be lacking in basic features as a result of oversimplifying user interaction for the sake of appealing to the average consumer - this is not one such password manager.

### You shouldn't use Krypton if...
- You're unfamiliar with the command line, or dislike using it.
- You can't live without a mobile app or browser extension (coming in the future).
- You favor mouse controls over keyboard controls.
- You have an aversion to learning curves.
- You value convenience over privacy.

---

### You should use Krypton if...
- You want direct control over how and where your encrypted credentials are stored.
- You don't want to sign up for anything, or give your data to anyone.
- You want more advanced functionality out of your password manager.
- You're more comfortable with a command line, or find it more efficient than a GUI.
- You have Python experience, and want a password manager that can be easily tweaked or extended.

## Dependencies
- [PyCryptoDome](https://pypi.org/project/pycryptodome/) - Cryptography Library
- [Pyperclip3](https://pypi.org/project/pyperclip3/) - Cross-platform Clipboard Access
```
python -m pip install pycryptodome pyperclip3
```

## Basic Operations (demo)
Here are some examples on how you would do some basic common operations in Krypton. A more [comprehensive command reference](#Krypton-Command-Reference) can be found further down.

### Create New Vault
![new_vault_10fps](https://user-images.githubusercontent.com/34726837/190071642-08211965-f2b8-4a49-a16e-a1c3c329269b.gif)

### Create New Account & Save Changes
![new_account_and_save_10fps](https://user-images.githubusercontent.com/34726837/190071689-ced3a001-f53e-48e6-b74a-73249167ab00.gif)

### Make Changes, View Changes, Revert Changes
![change_and_revert_10fps](https://user-images.githubusercontent.com/34726837/190071729-1c7884fc-3007-429f-aaad-985f3f63d5fb.gif)

### Load Vault & Copy/Retrieve Value
![load_and_copy_10fps](https://user-images.githubusercontent.com/34726837/190071763-28c92310-9ae2-468c-bc06-1ee10639a02a.gif)

### Cycle Pages, Page Rows, Search Filters
![view_options_10fps](https://user-images.githubusercontent.com/34726837/190071784-b7076ee9-bba0-43cf-8f89-c22ace5d94dc.gif)

### Create New Vault From JSON
![vault_from_json_10fps](https://user-images.githubusercontent.com/34726837/190071819-b2543255-1b7b-4a2d-ab98-44e25f0e9a59.gif)

## Krypton Command Line Arguments
This is the command line argument reference for Krypton, automatically generated via argparse. Comand line arguments are not used to directly interact with Krypton; scroll down for the command reference.
```
usage: krypton.py [-h] --file [VAULT_PATH] [--ivmask [IV_MASK_LENGTH]] [--insecure] [--debug]

options:
  -h, --help            Show this help message and exit.

  --file [VAULT_PATH], -f [VAULT_PATH]
                        A path pointing to the vault file that should be created or loaded.

  --ivmask [IV_MASK_LENGTH], -ivm [IV_MASK_LENGTH]
                        The amount of random bytes that should be added or stripped from the start of the encryption/decryption output in order to mask the IV; should be
                        16 at the very least (AES block size).

  --insecure, -is       When present, this flag makes the program treat the file pointed to by --file as an unencrypted insecure vault, decryption will not be attempted.
                        This also affects the encryption of newly created vaults.

  --debug, -db          This flag enables the printing of additional information for debugging purposes.
```

## Krypton Command Reference
This is the command reference for Krypton, here you can find all of the relevant commands for interacting with this password manager. You can view a copy of this reference within Krypton by using the `help` command. This does not include the command line arguments, to view those use the `--help` or `-h` argument when running Krypton.
```
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
```

"""
CypherVault - Command Line Password Manager

litepresence2019

writes site login to clipboard w/ xclip; auto deletes in 10 seconds
reads/writes AES CBC encrypted password json to text file
new salt after every successful login, password change, return to main menu, and exit
salt is 16 byte and generated in crypto secure manner
master password stretched to several hundred megabytes
master password hashed iteratively via traditional pbkdf
master password rehashed iteratively via non traditional method

references:
https://stackoverflow.com/questions/43860227/python-getting-and-setting-clipboard-data-with-subprocesses
https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
https://datalocker.com/what-is-the-difference-between-ecb-mode-versus-cbc-mode-aes-encryption
https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html
https://docs.oracle.com/cd/E11223_01/doc.910/e11197/app_special_char.htm
https://docs.python.org/3/library/hashlib.html
https://crackstation.net/hashing-security.htm
https://en.wikipedia.org/wiki/PBKDF2
https://www.owasp.org
"""

# STANDARD PYTHON MODULES
import os
import sys
import time
import string
import struct
import traceback
from stat import S_IREAD
from hashlib import sha512
from hashlib import blake2b as blake
from hashlib import sha3_512 as sha3
from hashlib import pbkdf2_hmac as pbkdf
from hashlib import shake_256 as shake256
from base64 import b64encode, b64decode
from json import loads as json_loads
from json import dumps as json_dumps
from subprocess import Popen, PIPE
from random import seed, randint, shuffle
from binascii import hexlify
from getpass import getpass

# THIRD PARTY MODULES
# WARNING: "pip install pycryptodome" NOT the deprecated "pycrypto"
from Crypto import Random
from Crypto.Cipher import AES


# USER DEFINED SECURITY CONSTANTS
# WARNING: when you change these parameters your CypherVault will need to be deleted
MEGABYTES = 400
ITERATIONS = 1000000

# CURRENT RELEASE ID
VERSION = 0.00000005

# WORKING DIRECTORY
PATH = str(os.path.dirname(os.path.abspath(__file__))) + "/"

# FORMATTING METHODS
def banner():
    """
    prepare a banner for use by wallet_main() and wallet_initialize()
    """
    return f"""
    ******************************************
    *** Welcome to CypherVault v{VERSION:.8f} ***
    ******************************************\n
    """


def it(style, text):
    """
    colored text in terminal
    """
    emphasis = {
        "green": 92,
        "purple": 95,
    }
    return f"\033[{emphasis[style]}m{str(text)}\033[0m"


def trace():
    """
    Stack trace report upon exception
    """
    return "\n\n".join([time.ctime(), traceback.format_exc()])


# READ / WRITE METHODS
def doc_write(document, text):
    """
    write a dictionary to file
    """
    with open(document, "w+") as handle:
        handle.write(text)


def doc_read(document):
    """
    read dictionary from file
    """
    with open(document, "r") as handle:
        return handle.read()


# CLIPBOARD METHODS
def clip_get():
    """
    read from clipboard
    """
    clip = Popen(["xclip", "-selection", "clipboard", "-o"], stdout=PIPE)
    clip.wait()
    return clip.stdout.read().decode()


def clip_set(data):
    """
    write to clipboard
    """
    clip = Popen(["xclip", "-selection", "clipboard"], stdin=PIPE)
    clip.stdin.write(data.encode())
    clip.stdin.close()
    clip.wait()


# CRYPTOGRAPHY METHODS
def crypto_pad(msg):
    """
    pad if length is not a multiple of 128 else unpad as required
    """
    return (
        (msg + (128 - len(msg) % 128) * chr(128 - len(msg) % 128))
        if len(msg) % 128
        else msg[0 : -msg[-1]]
    )


def crypto_100():
    """
    cryptographically secure 100 digit string formatted integer generator
    """
    str_random = ""
    while len(str_random) != 100:
        set_random = struct.unpack("QQQQQQ", os.urandom(48))
        str_random = ""
        for integer in set_random:
            str_random += str(integer)
        str_random = str(int(str_random[-100:]))
    return str_random


def crypto_wacky_digest(msg_digest, salt):
    """
    never roll your own... except as a backup plan and fun learning experience!
    random amount of multiple hashing types to impose novelty restraint
    """
    shaken_salt = shake256(salt.encode()).digest(16)
    # randomized iteration count
    for _ in range(int(salt[-4:])):
        # for each up to 10 iterations; 1 in 10 no skip
        for _ in range(int(salt[-1])):
            # salted 512 chacha stream cipher with permuted input block copy
            msg_digest = hexlify(blake(msg_digest, salt=shaken_salt).digest())
        for _ in range(int(salt[-2])):
            # keccak 512 sponge construction
            msg_digest = sha3(msg_digest).digest()
        for _ in range(int(salt[-3])):
            # standard sha512
            msg_digest = sha512(msg_digest).digest()

    return msg_digest


def crypto_digest(password):
    """
    iterative rounds of hashing to impose time restraint
    expanded password length to impose memory restraint
    """
    # any scheme which uses more than a few hundred MB of RAM
    # is almost certainly inefficient for GPU or FPGA implementations
    password *= max(1, int(MEGABYTES * 10 ** 6 / len(password)))
    # shake and digest the salt to 16 bytes
    salt = doc_read("cyphervault.txt").split("$", 1)[0]
    shaken_salt = shake256(salt.encode()).digest(16)
    # many iterations of salted 512 password based key derivation function (PBKDF)
    msg_digest = hexlify(pbkdf("sha512", password.encode(), shaken_salt, ITERATIONS))
    # multiple types of hashing to impose novelty restraint
    msg_digest = crypto_wacky_digest(msg_digest, salt)
    # final format to sha256 for 32 byte output
    return shake256(msg_digest).digest(32)


def crypto_cypher(vector, password):
    """
    AES encryption method in CBC mode
    """
    return AES.new(crypto_digest(password), AES.MODE_CBC, vector, segment_size=256)


def crypto_encrypt(message, password):
    """
    encryption routine
    """
    vector = Random.new().read(AES.block_size)
    cypher = crypto_cypher(vector, password)
    recursion = cypher.encrypt(crypto_pad(message))
    return b64encode(vector + recursion)


def crypto_decrypt(cyphertext, password):
    """
    decryption routine
    """
    vector = b64decode(cyphertext)
    cypher = crypto_cypher(vector[:16], password)
    recursion = cypher.decrypt(vector[16:])
    return crypto_pad(recursion).decode()


def crypto_indite(passwords):
    """
    \nencrypting the CypherVault...
    """
    print(it("purple", crypto_indite.__doc__))
    cyphersalt = crypto_100()
    cyphervault = doc_read("cyphervault.txt").split("$", 1)[1]
    doc_write(
        "cyphervault.txt", cyphersalt + "$" + cyphervault,
    )
    cyphervault = crypto_encrypt(
        json_dumps(passwords), passwords["master"]["master"]
    ).decode()
    doc_write(
        "cyphervault.txt", cyphersalt + "$" + cyphervault,
    )


# WALLET METHODS
def wallet_main(passwords):
    """
    1: ENTER A NEW PASSWORD OR EDIT A PASSWORD
    2: DELETE A PASSWORD
    3: SUGGEST A PASSWORD
    4: ENTER JSON PASSWORDS
    5: PRINT JSON PASSWORDS 
    6: PRINT SITE/USER LIST PLAIN TEXT
    7: EXIT
    """
    crypto_indite(passwords)
    sites_without(passwords)
    while True:
        print("\033c", it("green", banner()), it("green", wallet_main.__doc__))
        choice = input("input choice or press Enter to GET A PASSWORD: ") or "0"
        if choice.isdigit():
            choice = int(choice)
            if 0 <= choice <= 7:
                break
        print(f"\033c\n\n\n\tinvalid choice < {it('green', choice)} > try again")
        time.sleep(2)
    menu = {
        0: option_get,
        1: option_post,
        2: option_delete,
        3: option_suggest,
        4: option_import_json,
        5: option_print_full,
        6: option_print,
        7: crypto_indite,
    }
    menu[choice](passwords)
    if choice == 7:
        sys.exit()


def wallet_initialize(master):
    """
    initialize password dictionary and prompt for master password
    """
    # read password dictionary if none exists create a new encrypted cyphervault
    # all passwords are in format >>> passwords[site][user]
    print("\033c", it("green", banner()))
    try:
        cyphervault = doc_read("cyphervault.txt").split("$", 1)[1]
        assert cyphervault
    except Exception:
        print("\nCypherVault not found, intitializing new...")
        doc_write("cyphervault.txt", (crypto_100() + "$n"))
        passwords = {"master": {"master": "password"}}
        crypto_indite(passwords)
        cyphervault = doc_read("cyphervault.txt").split("$", 1)[1]
        print(it("purple", "\nyour default password is has been set to:"))
        print(it("green", "\npassword\n"))
    if master is None:
        master = getpass("Enter your master password:  ")
    # attempt to decrypt the cyphervault with the supplied password
    decrypted = False
    try:
        passwords = json_loads(crypto_decrypt(cyphervault, master))
        decrypted = True
    except Exception:
        trace()
        print(it("green", "\ninvalid master password, press Enter to try again..."))
        input("\npress Enter to return to main menu")
        wallet_initialize(master=None)  # recursion
    if decrypted:
        print(it("green", "\n    login successful!"))
        # warn if password is default
        if master == "password":
            print(it("purple", "\nyou should change default password immediately!"))
            print("\nyour master password is: ", it("green", master))
            input("\npress Enter to continue")
        # perform some tests on the password
        audit(master)
        wallet_main(passwords)


# WALLET OPTION METHODS
def option_get(passwords):
    """
    the password has been copied to the clipboard
    \nyou only have 10 seconds to paste it via ctrl+V
    """
    site, user = input_site_user()
    found = False
    if site in passwords.keys():
        if user in passwords[site].keys():
            found = True
            clip_set(passwords[site][user])
            print(it("purple", option_get.__doc__))
            time.sleep(10)
            clip_set("")
            print("clipboard has been cleared")
            time.sleep(2)
    if not found:
        print("\nsite/user not found in wallet")
        response = input("\nwould you like to add this site/user? (y/n):  ")
        if response in ["", "y", "Y"]:
            option_post(passwords, site, user)
    input("\npress Enter to return to main menu")
    wallet_main(passwords)


def option_post(passwords, site=None, user=None):
    """
    post a new or updated password to the cyphervault
    """

    def update(passwords, site, user):
        """
        input password and edit the CypherVault
        """
        print(it("purple", "\nsite/user:"), site, user, "\n")
        # double Enter the new password
        new_pass = getpass("\ninput password: ")
        if new_pass == getpass("\ninput new password again: "):
            audit(new_pass)
            if site not in passwords.keys():
                passwords[site] = {}
            passwords[site][user] = new_pass
            crypto_indite(passwords)
            print(it("green", "\nCypherVault has been updated"))
            time.sleep(1)
        else:  # recursion
            print(it("purple", "\npasswords do not match, try again..."))
            time.sleep(2)
            update(passwords, site, user)

    if site is None:
        site, user = input_site_user()
    create_new = True
    # update a password if it already exists
    if site in passwords.keys():
        if user in passwords[site].keys():
            print("\nsite:", site, "\nuser:", user)
            print(it("purple", "\nWARN: site/user already exists"))
            time.sleep(1)
            response = input("\nwould you like to overwrite this site/user? (y/n):")
            if response not in ["", "y", "Y"]:
                create_new = False
    if create_new:
        update(passwords, site, user)
    # return to main menu
    input("\npress Enter to return to main menu")
    wallet_main(passwords)


def option_delete(passwords):
    """
    remove a user from the cyphervault
    """
    print("\nEnter the site and user you would like to delete")
    site, user = input_site_user()
    if site != "master":
        found = False
        # check if the site/user exists in the passwords
        if site in passwords.keys():
            if user in passwords[site].keys():
                found = True
        if found:
            # remove the user
            del passwords[site][user]
            if passwords[site] == {}:
                # if there are no other users at that site, remove the site as well
                del passwords[site]
                crypto_indite(passwords)
                print(it("purple", "\nsite/user has been deleted"))
                time.sleep(1)
        else:
            # return to the main menu
            print(it("purple", "\nsite/user was not found"))
            time.sleep(1)
    else:
        print(it("purple", "you cannot delete the master password!"))
    input("\npress Enter to return to main menu")
    wallet_main(passwords)


def option_print(passwords):
    """
    print all site/user combinations in the cyphervault
    """
    print("")
    for site, logins in passwords.items():
        for user in logins.keys():
            if user == site:
                print(it("green", site))
            else:
                print(it("green", site + " : " + user))
    time.sleep(1)
    input("\npress Enter to return to main menu")
    wallet_main(passwords)


def option_print_full(passwords):
    """
    \n\n
    WARNING: YOU ARE ABOUT TO EXPOSE YOUR UNENCRYPTED CYPHERVAULT
    Make sure you are in a private location!\n
    WARNING: DO NOT PRINT THIS TO PAPER
    CypherVault contents will be exposed on your printer hard drive\n
    WARNING: DO NOT SAVE THIS TO FILE
    CypherVault contents will be exposed on your local hard drive\n
    USE THIS FUNCTION ONLY TO INSPECT OR COPY - BY HAND - TO PAPER\n\n
    """
    print("\033c", it("purple", option_print_full.__doc__))
    msg = "\nare you sure you want to print your unencrypted CyperVault (y/n):  "
    response = input(it("green", msg))
    if response in ["y", "Y"]:
        input("\npress Enter to expose the CypherVault\npress Enter again to exit\n")
        print("\033c\n\n\n")
        print(it("green", json_dumps(passwords, indent=0, sort_keys=True)))
    input("press Enter to return to main menu")
    wallet_main(passwords)


def option_suggest(passwords, length=12):
    """
    this password is on your clipboard, ctrl+V to paste\n
    press Enter to suggest another secure random password\n
    or any number 10 to 500, then Enter to change the length\n
    or any other key, then Enter to return to main menu\n\n\t
    """

    def cluster(password):
        """
        format password into blocks of numbers, letters, and symbols 
        """

        def split(string):
            """
            split string into blocks
            """
            length = randint(3,4)
            return [string[i : i + length] for i in range(0, len(string), length)]

        digits = ""
        uppers = ""
        lowers = ""
        others = ""
        for char in password:
            if char.isdigit():
                digits += char
            elif char.isupper():
                uppers += char
            elif char.islower():
                lowers += char
            else:
                others += char

        cluster_list = (
            split(digits) + split(lowers) + split(uppers) + [i for i in others]
        )
        shuffle(cluster_list)

        return "".join(cluster_list)

    response = ""
    while not response:
        # letters, numbers, and Oracle approved symbols
        chars = string.ascii_letters + string.digits + "?%^*+~-=[]{}:,.#_"
        legit = False
        while not legit:

            seed(int(crypto_100()))
            password = ""
            for _ in range(length):
                password += str(chars[randint(0, len(chars) - 1)])
            password = cluster(password)
            legit = audit(password, display=False)

        print("\033c\n   ", it("green", password), "\n")
        clip_set(password)
        response = input(option_suggest.__doc__)
        print("")
        if response.isdigit():
            response = int(response)
            if response < 10:
                input("minimum suggested length is 10, press Enter to continue")
                length = 10
            if response > 500:
                input("maximum supported length is 500, press Enter to continue")
                length = 500
            else:
                length = response
            response = ""
        elif response:
            wallet_main(passwords)


def option_import_json(passwords):
    """
    use this utility to import and append a password dictionary
    via cut and paste from text editor
    it must be properly formatted JSON, example:\n
    {"site_name":{"user_name":"your_password"}}\n
    which is the same format as menu choice\n
    PRINT SITE/USER/PASSWORD LIST JSON\n
    for email addresses site and user must match\n
    DO NOT save the text document!
    use an "untitled" text document,
    so it does not autosave and remains in RAM!\n
    to skip and return to main menu, press Enter\n 
    """
    print("\033c\n\n\n", it("green", option_import_json.__doc__))
    json_doc = input("enter your JSON formatted password list:  ")
    if json_doc:
        try:
            dictionary = json_loads(json_doc)
            try:
                d_is = isinstance(dictionary, dict)
                for k, v in dictionary.items():
                    k_is = isinstance(k, str)
                    v_is = isinstance(v, dict)
                    for k2, v2 in v.items():
                        k2_is = isinstance(k, str)
                        v2_is = isinstance(k, str)
                valid = d_is and k_is and v_is and k2_is and v2_is
                if not valid:
                    raise ValueError
            except ValueError:
                trace()
                msg = """
                    improperly formatted passwords dictionary\n\n
                    press Enter to return to main menu
                    """
                input(msg)
                wallet_main(passwords)
            passwords.update(dictionary)
            crypto_indite(passwords)
            print(it("green", "\nCypherVault successfully updated!"))
            wallet_main(passwords)
        except ValueError:
            trace()
            input("invalid json\n\npress Enter to return to main menu")
    clip_set("")
    wallet_main(passwords)


# INPUT AND ANALYSIS METHODS
def input_site_user():
    """
    routine to input site and user name
    """
    site = input("\nEnter site name:  ")
    if (("@" in site) and (".com" in site)) or (site == "master"):
        user = site
    else:
        user = input("\nEnter user name:  ")
    print("")
    return site, user


def audit(password, display=True):
    """
    \nyour password is weak, you should change it!
    \naim for length greater or equal to 10
    \nand 2 each unique uppers, lowers, digits, symbols\n
    """
    uppers = []
    lowers = []
    digits = []
    others = []
    for item in [c for c in password]:
        if item.isupper():
            uppers.append(item)
        elif item.islower():
            lowers.append(item)
        elif item.isdigit():
            digits.append(item)
        else:
            others.append(item)
    length = len(password)
    uppers = len(list(set(uppers)))
    lowers = len(list(set(lowers)))
    digits = len(list(set(digits)))
    others = len(list(set(others)))
    review = {
        "length": length,
        "unique uppers": uppers,
        "unique lowers": lowers,
        "unique digits": digits,
        "unique symbols": others,
    }
    legit = True
    if not ((length >= 10) and (min(uppers, lowers, digits, others) >= 2)):
        legit = False
        if display:
            print(it("purple", audit.__doc__), it("green", "audit:"), review)
            input("\npress Enter to continue")
    return legit


def read_only():
    """
    require sudo to edit CypherVault.py
    """
    os.chmod(PATH+"cyphervault.py", S_IREAD)


def sites_without(passwords):
    """
    maintain a list of user accounts in JSON format in CypherVault_accounts.txt
    """
    accounts = {k:{k2:"" for k2,v2 in v.items()} for k,v in passwords.items()}
    doc_write(
        "CypherVault_accounts.txt",
        json_dumps(accounts, indent=0, sort_keys=True)
    )

    
def pycryptodome():
    """
    \nTEST FAILED!\n\n
    "pycrypto" is not maintained and has been replaced by "pycryptodome"\n
    packages installed on your system:\n
    """
    print("\033c\n\nensuring", it("green","pycryptodome"), "is installed...")   
    print("ensuring pycrypto is", it("purple","NOT"), "installed...")
    p = Popen(["pip", "show", "pycrypto"], stdout=PIPE)
    out_pycrypto, _ = p.communicate()
    p = Popen(["pip", "show", "pycryptodome"], stdout=PIPE)
    out_pycryptodome, _ = p.communicate()
    out_pycrypto = out_pycrypto.decode()
    out_pycryptodome = out_pycryptodome.decode()
    if (("Version" in out_pycrypto) or not ("Version" in out_pycryptodome)):
        print(it("purple", pycryptodome.__doc__), out_pycryptodome, out_pycrypto)
        raise ValueError(it("green", "pip3 install pycryptodome"))
    else:
        print(it("purple", "\n\nTEST PASSED!\n\n"))
        time.sleep(1)

if __name__ == "__main__":

    pycryptodome() # comment out this line to skip test
    read_only()
    wallet_initialize(master=None)

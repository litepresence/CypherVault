# CypherVault

Command Line Password Manager
-----------------------------

litepresence2019

    writes site login to clipboard w/ xclip; auto deletes in 15 seconds
    reads/writes AES CBC encrypted password json to text file
    new salt after every successful login, password change, return to main menu, and exit
    salt is 16 byte and generated in crypto secure manner
    master password stretched to several hundred megabytes
    master password hashed iteratively via traditional pbkdf
    master password rehashed iteratively via non traditional method


---------------------------------------- PASSWORD CRACKER --------------------------------------------

name:		Ofir Haruvi

------------------------------------------------------------------------------------------------------


A password-cracking tool that breaks MD5, SHA1, and SHA256 hashes using a dictionary attack. 

The tool supports two input formats:

For cracking a single hashed string:
s, <hashed_password>, <hash_algorithm (MD5, SHA1, SHA256)>, <password_dictionary_file_path>

For cracking multiple hashes from a file:
f, <hashed_password_file_path>, <hash_algorithm (MD5, SHA1, SHA256)>, <password_dictionary_file_path>

It returns the cracked passwords in a Python dictionary, where each hash is paired with its 
corresponding password.
import hashlib
import pyfiglet


# banner of the program
def banner():
    ascii_banner = pyfiglet.figlet_format("Pass Cracker")  # banner
    print(ascii_banner)


# instructions for the user input
def instructions():
    print(
        """
        Please enter the input in one of the following formats:
        
        1. For a single hashed string:
            s, <hashed_password>, <hash_algorithm (MD5, Sha1, Sha256)>, <password_dictionary_file_path>
        2. For a file of hashed passwords:
            f, <hashed_password_file_path>, <hash_algorithm (MD5, Sha1, Sha256)>, <password_dictionary_file_path>
        """)


# user input according to instructions
def user_command():
    print("Enter a command: ")
    command = input()
    return command


# split a command to sections, by ", " separator
def command_spliter(command):
    split_command = command.split(', ')
    return split_command


# split the user input into sections, and put them one after the other in a list
def user_input():
    command_list = command_spliter(user_command())
    return command_list


# return true if the user want to decode hashes from a file or false if he wants to decode a string.
# if the password type is unrecognized - exiting the program.
def is_file(file_or_str):
    if file_or_str == 'f':
        return True
    elif file_or_str == 's':
        return False
    else:
        print("unrecognized password type [not s or f]. exiting the program")
        exit()


# check which hash algorithm has been chosen and format it as it used in the hashlib library.
# if the hash algorithm is not supported or invalid - exiting the program.
def which_hash(hash_type):
    match hash_type.lower():
        case "sha1":
            return "SHA1"
        case "sha256":
            return "SHA256"
        case "md5":
            return "MD5"
        case _:
            print("Hash algorithm not supported or invalid. Exiting program.")
            exit()


# check if file exist.
# if it does - return the file path. if not - exiting the program.
def file_exists(file_path):
    try:
        f = open(file_path, "r")
        f.close()
        return file_path
    except IOError:
        print("Error: File does not appear to exist.")
        exit()


# remove '\n' from a string. (for reading from file stage)
def remove_new_line_char(string):
    new_string = string
    return new_string.replace("\n", "")


# cracking the hash when there is a password list in a file
def hash_cracking_file(password, hash_type, path_dic):
    hash_pass = {}  # dictionary for matching hashes
    hash_file = open(password, "r")  # open hash file
    for hash_value in hash_file:
        hash_value_nl = remove_new_line_char(hash_value)  # remove new line characters from hash
        dic_file = open(path_dic, "r")  # open dictionary file
        for dic_pass in dic_file:
            dic_pass_nl = remove_new_line_char(dic_pass)  # remove new line characters from dictionary value
            h = hashlib.new(hash_type)  # choosing hash algorithm
            h.update(dic_pass_nl.encode())  # choosing the current dictionary value
            if hash_value_nl == h.hexdigest():  # if the hash values match
                hash_pass[hash_value_nl] = dic_pass_nl  # adding the matching pair to the dictionary
    dic_file.close()
    hash_file.close()
    return hash_pass


def hash_cracking_str(password, hash_type, path_dic):
    # cracking the hash when there is a password string
    hash_pass = {}  # dictionary for matching hashes
    dic_file = open(path_dic, "r")  # open dictionary file
    for dic_pass in dic_file:
        dic_pass_nl = remove_new_line_char(dic_pass)  # remove new line characters from dictionary value
        h = hashlib.new(hash_type)  # choosing hash algorithm
        h.update(dic_pass_nl.encode())  # choosing the current dictionary value
        if password == h.hexdigest():  # if the hash values match
            hash_pass[password] = dic_pass_nl  # adding the matching pair to the dictionary
    dic_file.close()
    return hash_pass


# function for cracking the hashes
def hash_cracking(file_pass_type, password, hash_type, pass_dic):
    dic_pass = {}
    if file_pass_type:  # cracking the hash when there is a password list in a file
        dic_pass = hash_cracking_file(password, hash_type, pass_dic)
    else:
        dic_pass = hash_cracking_str(password, hash_type, pass_dic)  # cracking the hash when there is a password string
    return dic_pass


# return true if the user wants to keep using the program and false otherwise
def keep_cracking():
    leave = input("To leave the program type 'q'. to stay, type anything else.\n")
    if leave == 'q':
        return False
    return True


def main():
    hash_pass = {}
    banner()
    instructions()
    working_flag = True
    while working_flag:
        user_command_list = user_input()  # getting the user input
        file_pass_type = is_file(user_command_list[0])  # saves the password file type
        password = ""
        if file_pass_type:  # saves the password
            password = file_exists(user_command_list[1])  # if it is a string
        else:
            password = user_command_list[1]  # if it is a file path
        hash_type = which_hash(user_command_list[2])  # saves the hash algorithm
        dic_path = file_exists(user_command_list[3])  # saves the dictionary file path
        hash_pass = hash_cracking(file_pass_type, password, hash_type, dic_path)  # cracking the hashes
        print(hash_pass)  # print the cracked hashes
        print()
        working_flag = keep_cracking()  # check if the user wants to quit or to keep using the program


if __name__ == '__main__':
    main()

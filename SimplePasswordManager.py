import hashlib

def hash_password(password):

    hashed_password = hashlib.sha256(password.encode()).hexdigest() # hashes the password using SHA-256 & 
    return hashed_password                                          # returns it in hash form

def save_password(username, password):

    with open("passwords.txt", "a") as file:  # opens a file named passwords.txt 
        file.write(f"{username}:{password}\n") # saves the usename and password to the file

def retrieve_password(username):
    
    with open("passwords.txt", "r") as file: # function is used to retrieve password after username is inputted from user
        for line in file:
            stored_username, stored_password = line.strip().split(":")
            if stored_username == username:
                return stored_password
    return None

def main(): # interacts w/ user to ask for username and password
   
    print("Welcome to Simple Password Manager!")

    while True:
        choice = input("Enter '1' to save a password, '2' to retrieve a password, or '3' to exit: ")

        if choice == '1': # if user enters '1' the program asks for a username and password
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            hashed_password = hash_password(password) # hashes the inputted password
            save_password(username, hashed_password)
            print("Password saved successfully!")
        elif choice == '2': # if '2' is entered program asks for a username to identify a password
            username = input("Enter the username for which to retrieve the password: ")
            stored_password = retrieve_password(username)
            if stored_password:
                print(f"The password for {username} is: {stored_password}") # prints username and hashed password
            else:
                print("Username not found.")
        elif choice == '3': # '3' is used to exit the program
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter '1', '2', or '3'.")

if __name__ == "__main__":
    main()

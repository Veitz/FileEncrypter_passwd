 
## File Encryption with Password  
A small console program which encrypts and decrypts files. For decryption the 'salt.salt' file is needed. 

**Output:**  

![image description](https://i.ibb.co/rtZwxXf/fileencrypter.png)

Please try it with test data first!  

**Requirements**

linux
- `sh requirements.sh`
 
windows  
- `requirements.cmd`  

install python3: https://www.python.org/  

* `sudo apt install python3-pip` for pip3 on Ubuntu
* `pip3 install --upgrade pip`
* `pip3 install cryptography`
* `pip3 install secrets`
* `pip3 install pyfiglet`
* `pip3 install configparser`  



If you want to use a Keyfile (for network transaction), try this:
  ``` 
  # a tool to enrypt & decrypt files in python3
  # Fernet is an implementation of symmetric authenticated cryptography

  
  from cryptography.fernet import Fernet

  
  def generate_key():
      """
      Generates a key and save it into a file
      """
      key = Fernet.generate_key()
      with open("secure.key", "wb") as key_file:
          key_file.write(key)

  
  def load_key():
      """
      Loads the key from the current directory named `key.key`
      """
      return open("secure.key", "rb").read()

  
  def encrypt(filename, key):
      """
      Given a filename (str) and key (bytes), it encrypts the file and write it
      """
      f = Fernet(key)
      with open(filename, "rb") as file:
          # read all file data
          file_data = file.read()
          # encrypt data
          encrypted_data = f.encrypt(file_data)
      # write the encrypted file
      with open(filename, "wb") as file:
          file.write(encrypted_data)


  def decrypt(filename, key):
      """
      Given a filename (str) and key (bytes), it decrypts the file and write it
      """
      f = Fernet(key)
      with open(filename, "rb") as file:
          # read the encrypted data
          encrypted_data = file.read()
      # decrypt data
      decrypted_data = f.decrypt(encrypted_data)
      # write the original file
      with open(filename, "wb") as file:
          file.write(decrypted_data)


  ### run ###
  generate_key()  # generate the key to encrypt & decrypt, keyfile calls secure.key
  key = load_key() # load the key from file 'secure.key'
  file = "test.csv" # thats the filename to encrypt
  encrypt(file, key) # encrypt the file
  decrypt(file, key) # decrypt the file
  ```

# RansomEDUware

## Introduction
This is a **ransomEDUware** for *educational*. This program is using the *openSSL library* for encrypting & decrypting file.
This code has **no leak of memory** *(checked with valgrind)*. 
All advice are welcome, it's my first program in C (with the collaboration of another person). :smile:

## Way to use
### Requirements
- *Linux system*
- *The library openSSL installed*
- *A responsible brain*
> to install the openSSL library, you have to do `sudo apt install libssl-dev`
### Compilation
i've used gcc to compile this with the command `gcc -o main.c FILENAME -lcrypto`. The `-lcrypto` argument is for the library openSSL.

### Command
    __________                                    ___________________   ____ ___                                
    \______   \_____    ____   __________   _____ \_   _____/\______ \ |    |   \__  _  _______ _______   ____  
     |       _/\__  \  /    \ /  ___/  _ \ /     \ |    __)_  |    |  \|    |   /\ \/ \/ /\__  \\_  __ \_/ __ \ 
     |    |   \ / __ \|   |  \\___ (  <_> )  Y Y  \|        \ |    `   \    |  /  \     /  / __ \|  | \/\  ___/ 
     |____|_  /(____  /___|  /____  >____/|__|_|  /_______  //_______  /______/    \/\_/  (____  /__|    \___  >
     \/      \/     \/     \/            \/        \/         \/                        \/            \/

                ------------------------- Way to use ------------------------------
                ------------------- To encrypt : -crypt <PATH> --------------------
                -------------- To decrypt : -decrypt <PATH> <KEY> <IV> ------------

>To see this menu you can run the program without any arguments

### Sending message with socket
In the function `socket_msg()`, you have to change the ip address & the port that you want to send the key & the iv
*If you want to run the program on the same system, you don't have to change anything*
If you want to listen on the port that you choose, you can use `nc -ulp PORT`, in this code, it's the port 8888
> Reminder : you can't use this to encrypt a file that is not on the same linux computer as the program, the key&iv is only send to an ip address who listen on the same port

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import binascii
class base64():
    def encode(flag):
        char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        #flag = input("enter a string :")
        binary = ""
        chunks = []
        for i in flag:
            binary += bin(ord(i))[2:].zfill(8)

        
        for i in range(0, len(binary), 6):
                chunks.append(binary[i:i+6])

        
        for i in range(len(chunks)):
            if len(chunks[i]) < 6:
                    x = 6 - len(chunks[i])
                    chunks[i] = bin(int(chunks[i],2) << x)[2:].zfill(6)

        encoded_string = ""
        
        for i in chunks:
            encoded_string += char[int(i,2)]

        print(f"encoded string is :{encoded_string}")
        return encoded_string
        
    def decode(enc):
        char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        #enc = input("enter the string :")
        pp = []
        for i in range(0,len(enc)):
            for j in range(0, len(char)):
                if enc[i] == char[j]:
                    pp.append(int(j))
        
        binary = ''
        
        for num in pp:
            binary += "{0:06b}".format(int(num))            

    
        chunks = []

        for part in range(0, len(binary),8):
            chunks.append(binary[part : part+8])
        
    
        flag = ''
        for i in chunks:
            flag += chr(int(i,2))
        print(flag)
        return flag

class base32():
    def encode():
        char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        binary = ''
        string = input("Enter the string :")

        for letter in string:
            binary += "{0:08b}".format(ord(letter))
        
        chunks = []
        for i in range(0, len(binary), 5):
            chunks.append(binary[i:i+5])

        for i in range(len(chunks)):
            if len(chunks[i]) < 5:
                x = 5 - len(chunks[i])
                chunks[i] = "{0:05b}".format(int(chunks[i],2) << x)
        
        flag = ''

        for i in range(len(chunks)):
            flag += char[int(chunks[i],2)]

        print(flag)

    def decode():
        char = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        numbers = []

        enc = input("Enter the string :")

        for i in range(len(enc)):
            for j in range(len(char)):
                if enc[i] == char[j]:
                    numbers.append(int(j))
            
        binary = ''

        for i in numbers:
            binary += "{0:05b}".format(int(i))
        
        chunks = [binary[i:i+8] for i in range(0, len(binary), 8)]
        
        flag = ''

        for i in range(len(chunks)):
            flag += chr(int(chunks[i],2))
        
        print(flag)

def ceaser_encode(string, shift):
    encode_string = ""
    for char in string :
        if char.isalpha():
            if char.islower() :
                encode_char = chr((ord(char)-ord('a') - shift)%26 + ord("a"))
            else:
                encode_char = chr((ord(char)-shift-ord('A'))%26 + ord("A"))
            encode_string += encode_char
    
        else:
            encode_string += char
    print(encode_string)
    return encode_string

class base85():
    def encoder():
        char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+-;<=>?@^_`{|}~"
        string = input("Enter the string to encode :")
        chunks = []
        binary = ""
        flag = ''
        for character in string:
            binary += "{0:09b}".format(ord(character))
        
        #print(binary)

        
        for i in range(0, len(binary), 7):
            chunks.append(binary[i:i+7])

        n = len(chunks)-1

        if(len(chunks[n]) < 7):
            x = 7 - len(chunks[n])
            chunks[n] = "{0:07b}".format(int(chunks[n],2) << x)

        print(chunks)

        for i in range(len(chunks)):
            print(int(chunks[i], 2))
            flag += char[(int(chunks[i], 2)) % 85]
        
        print(flag)
     
class base16:
    def decoder():
        char = "abcdefghijklmnop"
        enc = input("enter the text please :")
        pp =[]
        for i in range(0, len(enc)):
            for j in range(0, len(char)):
                if (enc[i]== char[j]):
                    pp.append(int(j))

        binary = ''
        for num in pp:
            binary += "{0:04b}".format(int(num))

        print(binary)
        chunks = []
        
        for part in range(0, len(binary), 8):
            chunks.append(binary[part:part+8])
        
        print(chunks)
        flag = ''
        for i in chunks:

            flag += chr(int(i,2))

        print(flag)

def xor(arr1, arr2):
    dst = []
    for i in range(len(arr1)):
        dst.append(chr(ord(str(arr1[i])) ^ ord(str(arr2[i]))))
    return ''.join(dst)

flag = b"zeroday{*************}"
key = b"****************"

# ECB Encrypt
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(flag, AES.block_size))


# ECB Decrypt
#key = key1 + key2
cipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)



enc = (binascii.hexlify(ciphertext).decode())  
(base64.encode(enc))

#encoded string is :  ZDk2Y2I5ZjRjZGFiMzAwNjBjYTE3ZWRiMjljOTc2NGI2NmZmNGEzNzkxM2NiODlkNjkyMzc0OWFkYmU4Mjc2YzQ4ZDAwMWJlYzAxYTU2NjgzYTJkOGMxMzJiM2JlYWQ2

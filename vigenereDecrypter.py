#
##
## Vigenere Decrypter - Python Software
##
#

## Imports
from pathlib import Path
from math import fmod
import os
## Fetch Cipher from CipherText File (on the same level as Script) ##
#file = Path.joinpath('Resources', 'test.txt')
file = 'ciphertext.txt'
with open(file) as cipherFull:
    cipherFull = cipherFull.read()

## Remove whitespace from cipher ##
def ShortenCipher(cipher: str):
    return cipherFull.replace(' ', '')

## Define Global Variables 
cipher = (ShortenCipher(cipherFull)) # Short Function to make the cipher easier to work with, shortening it. 
cipherLength = len(cipher) # Checking length of new - shorter - cipher
AZ='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
cipherKey = "" 
AZL=len(AZ) # Length of Alphabet
EngCharFreq = [ # Table of Letter Frequencies # Source >> https://cs.wellesley.edu/~fturbak/codman/letterfreq.html
# Where first floating number in list below corresponds to the letter 'A', the second float to 'B' and so forth.
0.08167, 0.01492 , 0.02782, 0.04253 , 0.12702 , 
0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 
0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 
0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074]

## Calculate the Incidence of Coincidence Value of given input
def IOC(cipher: str) -> float:
    IC = 0
    cipherNum = len(cipher)    
    for letter in range(AZL):
        freq = cipher.count(chr(letter + 65)) ## 65 == ASCII Value of Uppercase ' A ' ## https://www.ascii-code.com/
        IC = float(IC) + freq * (freq - 1)
    return IC / (cipherNum * (cipherNum - 1)) # Calculation of the IC Value Here: N * (N - 1)

## Define the frequency rate of the letters in cipher compared to the english alphabet frequencies.
def FreqRate(cipher: str) -> float:
    fr = 0.0
    for x in range(AZL):
        freq = cipher.count(chr(x + 65)) / len(cipher)
        fr = fr + (freq-EngCharFreq[x])**2 # **=Exponent Operator
    return fr

## Define what the 'nth' character is based of how many parts the cipher has to be divided into.
def DivByNth(cipher: str, jump: int, nth: int) -> str:
    div = ""
    for x in range(len(cipher)):
        if fmod(x, nth) == jump: # fmod() to calculate the module of the specified given arguments.
            div = div + cipher[x]
    return div

## Shifting positions of cipher characters with alphabet to find out how many shifts needed.
## Using translate() together with zip() to iterate and return a modified string of given input
def Shifter(cipher: str, pos: int) -> int:
    shiftValue = 0
    # Slicing https://stackoverflow.com/questions/509211/understanding-slicing
    start = AZ[pos:] # items start through the rest of the array
    stop = AZ[:pos] # items from the beginning through stop-1
    shift = start + stop 
    shiftValue = cipher.translate({ ord(x):y for (x, y) in zip(AZ, shift) })
    return shiftValue

## Split Cipher into X amount of parts nessecary to find the key length 
def Seperator(cipher: str, partNum: int) -> str:
    global parts; 
    parts = [] # List of divided up parts of the cipher
    substr = '' 
    for x in range(partNum):
        for y in range(0, cipherLength, partNum):
            try:
                substr = substr + cipher[x + y]
            except:
                substr = substr + ''
        parts.append(substr)
        substr = ''
    return parts

## Uses the Seperator function to find the keyLength of used key. 
## When the IC Value of X amount of parts of cipher hits over 0.06 == keylength found!
def KeyLength(cipher: str) -> int:
    resultIC = IOC(cipher)
    keyLen=0
    while resultIC <= 0.06:
        keyLen += 1
        resultIC = 0
        substrings = Seperator(cipher, keyLen)
        for x in substrings:
            resultIC += IOC(x)
        resultIC = (resultIC / len(substrings))
        print('Cipher split into',keyLen,'parts - With an IC Value of', resultIC)
    return keyLen # Key Length Result <3

## Function to Assemble the actual key together, uses the Shifter() function together with FreqRate() function -
## to determine letter by letter of the cipher key. 
def KeyAssembler(cipher: str, kl: int) -> str:
    global cipherKey
    for x in range(0, kl):
        cut = DivByNth(cipher, (x), kl)
        neg = -1
        pos = 0
        for y in range(AZL):
            tempCut = Shifter(cut, - y) # Shifting through the already Divided Part
            fr = FreqRate(tempCut) # Checking Frequency Rate of the Shifted-Divided-Part
            while neg == -1:
                neg = fr
            while fr < neg:
                pos = y
                neg = fr
        cipherKey = cipherKey + chr(65 + pos) # for each y, mapping the values of ASCII/Unicode with given position to determine the key.
        print('Assembling Key:',pos,'-', cipherKey)
    return cipherKey

## Function to Decrypt the Encrypted Text with the found key using the Shifter() function. 
## Loops through the full range (0-10000) characters in cipher to decrypt it with the key.
def DecryptCipher(cipher: str, cipherKey: str) -> str:
    cipherInPlain = ""
    for x in range(len(cipher)):
        num = ((ord(cipherKey[ x % len(cipherKey)]) + 65 ) % AZL)
        cipherInPlain = cipherInPlain + Shifter(cipher[x], - num)
    return cipherInPlain

## Setting things together 
def Vigenere(cipher: str) -> str:
    
    # KeyLength of set key
    kl = KeyLength(cipher)
    print('======== The key is has a length of',kl,'characters! ========','\n')
    
    # Assembling The Key 
    cipherKey = KeyAssembler(cipher, kl)
    # Decrypting the Cipher with given cipherKey
    cipherInPlain = DecryptCipher(cipher, cipherKey)
    
    # Check IC Vaule of the Decrypted Cipher, if bigger or equals to 0.06, then return plaintext.
    resultIC = IOC(cipherInPlain)
    if resultIC >= 0.06:
        return cipherInPlain

## Finalize Output but adding back the nth(5) space in the Decrypted cipher / plaintext ##
def theEnd():
    final = Vigenere(cipher.upper())
    print('\n','================  DE-CODED MSG ================ ''\n',
    ' '.join([final[i:i+5] for i in range(0, len(final), 5)]))
    print('\n' '======== MESSAGE SUCCESSFULLY DECRYPTED WITH KEY ======== ','\n',
    '                    =',cipherKey,'=                ',)

## Final Print
theEnd()
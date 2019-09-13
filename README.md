# MD5 Cracker

Guess MD5 passwords using brute force.

The utility is written for educational purposes. 
With its help, without special difficulties, it is really possible to pick up a password 
with a length of 6-7 characters, so use longer passwords consisting of numbers, 
letters of different registers and also special characters. 
This will greatly complicate the password guessing.

Also, you should not use words from the dictionary, there is another algorithm 
that allows you to quickly and efficiently search through the dictionary.
There are several online password guessing services using this algorithm.

Parallel processing allows us to load the processor at 100%, which speeds up the selection. 
The code itself has not yet been optimized, but there is potential for improvement.

Differences from the original:

* Password length range.
* Progress display.
* Simplified code.

## Setup

Indicate all characters that are possible in the password in the variable `PasswordCrackerConsts::PASSWORD_CHARS`

# Compile

`mvn clean package`

JAR archive will be in the `/target` directory.

## Usage

`java -jar md5cracker-1.0-SNAPSHOT.jar numThreads minPasswordLength maxPasswordLength encryptedPassword`

### Example

`java -jar md5cracker-1.0-SNAPSHOT.jar 16 1 12 600f40849e66372838f2895a8a6d767b`

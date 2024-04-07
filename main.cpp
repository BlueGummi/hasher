#include <iostream>
#include <openssl/sha.h>
#include <fstream>
#include <openssl/evp.h>
#include "computehash.h"

// this is actually the worst code ever written
// Compile like this
// g++ -o main main.cpp -lcrypto
// Declares a function for SHA256

// Asks user to input thing to be hashed 
int main()
{
    int thingy {};

    std::string message = {};

    std::cout << "Input your message: ";

    std::getline(std::cin,  message);

    std::cout << "What type of hash would you like to use?\n";

    std::cout << "1. SHA (Secure Hash Algorithm)\n";

    std::cout << "2. MD (Message Digest Algorithm)\n";

    std::cout << "3. BLAKE\n";

    std::cout << "4. Other\n";

    std::cout << "Enter your selection: ";

    std::cin >> thingy;
    if (thingy==1){
    std::string three {};

    int option {};

    std::cout << "Would you like to use a SHA3 algorithm (yes or no)?: ";

    std::cin >> three;

    if(three=="no"){

    std::cout << "Select a hash algorithm \n";

    std::cout << "1. SHA-256 \n";

    std::cout << "2. SHA-512 \n";

    std::cout << "3. SHA-1 \n";

    std::cout << "4. SHA-384 \n";

    std::cout << "5. SHA-224 \n";

    std::cout << "Enter your choice: ";

    std::cin >> option;

    std::string yesorno {};

    std::cout << "Do you want to output the hash to a file (yes or no)?: ";

    std::cin >> yesorno;

    if (yesorno=="yes")

{

        std::string filename;

        std::cout << "What filename?: ";

        std::cin >> filename;

	std::ofstream file;

	std::string hashed {};

        switch (option)
	{

	case 1:
            hashed = sha256(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-256 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 2:
            hashed = sha512(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-512 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 3:
            hashed = sha1(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-1 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 4:
            hashed = sha384(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-384 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 5:
            hashed = sha224(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-224 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
    	}
    }
    // no
    if (yesorno=="no")
    {
	std::string hashed {};
	switch (option)
	{
	case 1:
            hashed = sha256(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-256 hash: " << hashed << "\n";
	    break;
	case 2:
            hashed = sha512(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-512 hash: " << hashed << "\n";
	    break;
	case 3:
            hashed = sha1(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-1 hash: " << hashed << "\n";
	    break;
	case 4:
            hashed = sha384(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-384 hash: " << hashed << "\n";
	    break;
	case 5:
            hashed = sha224(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA-224 hash: " << hashed << "\n";
	    break;
	}
    }
}

if (three=="yes"){

    std::cout << "Select a hash algorithm \n";

    std::cout << "1. SHA3-256 \n";

    std::cout << "2. SHA3-512 \n";

    std::cout << "3. SHA3-384 \n";

    std::cout << "4. SHA3-224 \n";

    std::cout << "Enter your choice: ";

    std::cin >> option;

    std::string yesorno {};

    std::cout << "Do you want to output the hash to a file (yes or no)?: ";

    std::cin >> yesorno;

    if (yesorno=="yes")

    {

        std::string filename;

        std::cout << "What filename?: ";

        std::cin >> filename;

	std::ofstream file;

	std::string hashed {};

        switch (option)
	{

	case 1:
            hashed = sha3_256(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-256 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 2:
            hashed = sha3_512(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-512 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 3:
            hashed = sha3_384(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-384 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	case 4:
            hashed = sha3_224(message);
            file.open (filename);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-224 hash: " << hashed << "\n";
            file << hashed << "\n";
            file.close();
	    break;
	}
    }
    // no
    if (yesorno=="no")
    {
	std::string hashed {};
	switch (option)
	{
	case 1:
            hashed = sha3_256(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-256 hash: " << hashed << "\n";
	    break;
	case 2:
            hashed = sha3_512(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-512 hash: " << hashed << "\n";
	    break;
	case 3:
            hashed = sha3_384(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-384 hash: " << hashed << "\n";
	    break;
	case 4:
            hashed = sha3_224(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "SHA3-224 hash: " << hashed << "\n";
	    break;
	}
    }
}
}
if (thingy==2)
{
     std::cout << "Select a hash algorithm \n";
     std::cout << "1. MDC2\n";
     std::cout << "2. MD5\n";
     std::cout << "3. MD5-SHA1\n";
     std::cout << "Enter your choice: ";
     int option {};
     std::cin >> option;
     std::string yesorno {};
     std::cout << "Do you want to output the hash to a file (yes or no)?: ";
     std::cin >> yesorno;
     if (yesorno=="yes")
     {
	     std::string filename;
	     std::cout << "What filename?: ";
	     std::cin >> filename;
	     std::ofstream file;
	     std::string hashed {};
	     switch (option)
	     {
		     case 1:
			     hashed = mdc2(message);
			     file.open (filename);
			     std::cout << "Original message: " << message << "\n";
			     std::cout << "MDC2 hash: " << hashed << "\n";
			     file << hashed << "\n";
			     file.close();
			     break;
                     case 2:
            		     hashed = md5(message);
            		     file.open (filename);
                             std::cout << "Original message: " << message << "\n";
            		     std::cout << "MD5 hash: " << hashed << "\n";
            		     file << hashed << "\n";
           		     file.close();
             		     break;
		     case 3:
           		     hashed = md5_sha1(message);
       			     file.open (filename);
		             std::cout << "Original message: " << message << "\n";
     		             std::cout << "MD5-SHA1 hash: " << hashed << "\n";
  		             file << hashed << "\n";
      		             file.close();
     		             break;
}
}
if (yesorno=="no")
{
        std::string hashed {};
        switch (option)
        {
        case 1:
            hashed = mdc2(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "MDC2 hash: " << hashed << "\n";
            break;
        case 2:
            hashed = md5(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "MD5 hash: " << hashed << "\n";
            break;
        case 3:
            hashed = md5_sha1(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "MD5_SHA1 hash: " << hashed << "\n";
            break;
        }
    }
}

if (thingy==3)
{
	 std::cout << "Select a hash algorithm \n";
     std::cout << "1. BLAKE256\n";
     std::cout << "2. BLAKE512\n";
     std::cout << "Enter your choice: ";
     int option {};
     std::cin >> option;
     std::string yesorno {};
     std::cout << "Do you want to output the hash to a file (yes or no)?: ";
     std::cin >> yesorno;
     if (yesorno=="yes")
     {
	     std::string filename;
	     std::cout << "What filename?: ";
	     std::cin >> filename;
	     std::ofstream file;
	     std::string hashed {};
	     switch (option)
	     {
		     case 1:
			     hashed = blake256(message);
			     file.open (filename);
			     std::cout << "Original message: " << message << "\n";
			     std::cout << "BLAKE256 hash: " << hashed << "\n";
			     file << hashed << "\n";
			     file.close();
			     break;
            case 2:
                hashed = blake512(message);
                file.open (filename);
                std::cout << "Original message: " << message << "\n";
                std::cout << "BLAKE512 hash: " << hashed << "\n";
                file << hashed << "\n";
                file.close();
                break;
}
}
if (yesorno=="no")
{
        std::string hashed {};
        switch (option)
        {
        case 1:
            hashed = blake256(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "BLAKE256 hash: " << hashed << "\n";
            break;
        case 2:
            hashed = blake512(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "BLAKE512 hash: " << hashed << "\n";
            break;
        }
    }

}
if (thingy==4)
{
    std::cout << "Select a hash algorithm \n";
     std::cout << "1. Whirlpool\n";
     std::cout << "2. RIPEMD160\n";
     std::cout << "Enter your choice: ";
     int option {};
     std::cin >> option;
     std::string yesorno {};
     std::cout << "Do you want to output the hash to a file (yes or no)?: ";
     std::cin >> yesorno;
     if (yesorno=="yes")
     {
	     std::string filename;
	     std::cout << "What filename?: ";
	     std::cin >> filename;
	     std::ofstream file;
	     std::string hashed {};
	     switch (option)
	     {
		     case 1:
			     hashed = whirlpool(message);
			     file.open (filename);
			     std::cout << "Original message: " << message << "\n";
			     std::cout << "Whirlpool hash: " << hashed << "\n";
			     file << hashed << "\n";
			     file.close();
			     break;
            case 2:
                hashed = ripemd(message);
                file.open (filename);
                std::cout << "Original message: " << message << "\n";
                std::cout << "RIPEMD160 hash: " << hashed << "\n";
                file << hashed << "\n";
                file.close();
                break;
}
}
if (yesorno=="no")
{
        std::string hashed {};
        switch (option)
        {
        case 1:
            hashed = whirlpool(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "Whirlpool hash: " << hashed << "\n";
            break;
        case 2:
            hashed = blake512(message);
            std::cout << "Original message: " << message << "\n";
            std::cout << "RIPEMD160 hash: " << hashed << "\n";
            break;
        }
    }
}
}

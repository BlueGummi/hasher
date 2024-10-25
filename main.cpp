#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <openssl/evp.h>

enum HashAlgorithm {
    SHA256 = 1,
    SHA512,
    SHA1,
    SHA384,
    SHA224,
    MD5,
    MD5_SHA1,
    BLAKE256,
    BLAKE512,
    WHIRLPOOL,
    RIPEMD160,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512
};

std::string computeHash(const std::string& str, const EVP_MD* md) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hashLength; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string hashMessage(int option, const std::string& message) {
    switch (option) {
        case SHA256: return computeHash(message, EVP_sha256());
        case SHA512: return computeHash(message, EVP_sha512());
        case SHA1:   return computeHash(message, EVP_sha1());
        case SHA384: return computeHash(message, EVP_sha384());
        case SHA224: return computeHash(message, EVP_sha224());
        case MD5:    return computeHash(message, EVP_md5());
        case MD5_SHA1: return computeHash(message, EVP_md5_sha1());
        case BLAKE256: return computeHash(message, EVP_blake2s256());
        case BLAKE512: return computeHash(message, EVP_blake2b512());
        case WHIRLPOOL: return computeHash(message, EVP_whirlpool());
        case RIPEMD160: return computeHash(message, EVP_ripemd160());
        case SHA3_224: return computeHash(message, EVP_sha3_224());
        case SHA3_256: return computeHash(message, EVP_sha3_256());
        case SHA3_384: return computeHash(message, EVP_sha3_384());
        case SHA3_512: return computeHash(message, EVP_sha3_512());
        default: return "";
    }
}

void outputHash(const std::string& message, const std::string& hashed, const std::string& filename) {
    std::cout << "Original message: " << message << "\n";
    std::cout << "Hash: " << hashed << "\n";

    if (!filename.empty()) {
        std::ofstream file(filename);
        file << hashed << "\n";
        file.close();
    }
}

int main() {
    std::string message;
    std::cout << "Input your message: ";
    std::getline(std::cin, message);

    int user_choice;
    std::cout << "What type of hash would you like to use?\n";
    std::cout << "1. SHA (Secure Hash Algorithm)\n";
    std::cout << "2. MD (Message Digest Algorithm)\n";
    std::cout << "3. BLAKE\n";
    std::cout << "4. Other\n";
    std::cout << "Enter your selection: ";
    std::cin >> user_choice;

    int option;
    std::string file_choice;
    std::string filename;

    if (user_choice == 1) {
        std::cout << "Select a hash algorithm \n";
        std::cout << "1. SHA-256 \n2. SHA-512 \n3. SHA-1 \n4. SHA-384 \n5. SHA-224\n";
        std::cout << "Enter your choice: ";
        std::cin >> option;
    } else if (user_choice == 2) {
        std::cout << "Select a hash algorithm \n1. MD5\n2. MD5-SHA1\n";
        std::cout << "Enter your choice: ";
        std::cin >> option;
    } else if (user_choice == 3) {
        std::cout << "Select a hash algorithm \n1. BLAKE256\n2. BLAKE512\n";
        std::cout << "Enter your choice: ";
        std::cin >> option;
    } else if (user_choice == 4) {
        std::cout << "Select a hash algorithm \n1. Whirlpool\n2. RIPEMD160\n";
        std::cout << "Enter your choice: ";
        std::cin >> option;
    }

    std::cout << "Do you want to output the hash to a file (yes or no)?: ";
    std::cin >> file_choice;

    if (file_choice == "yes") {
        std::cout << "What filename?: ";
        std::cin >> filename;
    }

    std::string hashed = hashMessage(option, message);
    outputHash(message, hashed, filename);
    
    return 0;
}

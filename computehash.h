#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <fstream>
#include <openssl/evp.h>
// this is actually the worst code ever written
// Compile like this
// g++ -o main main.cpp -lcrypto
// Declares a function for SHA256
#define computehash
std::string computeHash(const std::string& str, const EVP_MD* md)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hashLength; ++i)
    {
        ss << std::hex << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string sha256(const std::string &str)
{
    return computeHash(str, EVP_sha256());
}

std::string sha512(const std::string& str)
{
    return computeHash(str, EVP_sha512());
}

std::string sha1(const std::string& str)
{
    return computeHash(str, EVP_sha1());
}

std::string sha384(const std::string& str)
{
    return computeHash(str, EVP_sha384());
}

std::string sha224(const std::string& str)
{
    return computeHash(str, EVP_sha224());
}

std::string sha3_224(const std::string& str)
{
    return computeHash(str, EVP_sha3_224());
}

std::string sha3_384(const std::string& str)
{
    return computeHash(str, EVP_sha3_384());
}

std::string sha3_512(const std::string& str)
{
    return computeHash(str, EVP_sha512());
}

std::string sha3_256(const std::string& str)
{
    return computeHash(str, EVP_sha3_224());
}

std::string md5(const std::string& str)
{
    return computeHash(str, EVP_md5());
}

std::string md5_sha1(const std::string& str)
{
    return computeHash(str, EVP_md5_sha1());
}

std::string whirlpool(const std::string& str)
{
    return computeHash(str, EVP_whirlpool());
}

std::string ripemd(const std::string& str)
{
    return computeHash(str, EVP_ripemd160());
}

std::string mdc2(const std::string& str)
{
    return computeHash(str, EVP_mdc2 ());
}

std::string sm3(const std::string& str)
{
    return computeHash(str, EVP_sm3());
}

std::string blake256(const std::string& str)
{
    return computeHash(str, EVP_blake2s256());
}

std::string blake512(const std::string& str)
{
    return computeHash(str, EVP_blake2b512());
}

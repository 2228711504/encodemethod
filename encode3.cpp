#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

struct PutOption {
    bool encrypt = false;  // 是否加密存储
};

class KeyValueStore {
public:
    KeyValueStore() {
        const char* pubKeyPath = std::getenv("RSA_PUBLIC_KEY_PATH");
        const char* privKeyPath = std::getenv("RSA_PRIVATE_KEY_PATH");

        if (pubKeyPath == nullptr || privKeyPath == nullptr) {
            throw std::runtime_error("Environment variables RSA_PUBLIC_KEY_PATH or RSA_PRIVATE_KEY_PATH not set.");
        }

        loadPublicKey(pubKeyPath);
        loadPrivateKey(privKeyPath);

        std::cout << "Loaded public key from: " << pubKeyPath << std::endl;
        std::cout << "Loaded private key from: " << privKeyPath << std::endl;
    }

    bool put(const std::string& key, const std::string& value, const PutOption& option) {
        std::string data = value;
        std::string filename = key;

        if (option.encrypt) {
            data = encrypt(data);
            filename += ".enc";  // 使用.enc扩展名表示加密文件
        }

        std::ofstream file(filename, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file for writing: " << filename << std::endl;
            return false;
        }

        file.write(data.c_str(), data.size());
        file.close();
        return true;
    }

    bool get(const std::string& key, std::string& value) {
        std::string filename = key;
        bool isEncrypted = false;

        if (std::filesystem::exists(key + ".enc")) {
            filename += ".enc";
            isEncrypted = true;
        } else if (!std::filesystem::exists(key)) {
            std::cerr << "File not found: " << key << std::endl;
            return false;
        }

        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file for reading: " << filename << std::endl;
            return false;
        }

        std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (isEncrypted) {
            value = decrypt(data);
        } else {
            value = data;
        }

        return true;
    }

private:
    CryptoPP::RSA::PublicKey publicKey;
    CryptoPP::RSA::PrivateKey privateKey;

    void loadPublicKey(const char* filePath) {
        CryptoPP::FileSource file(filePath, true);
        publicKey.Load(file);
    }

    void loadPrivateKey(const char* filePath) {
        CryptoPP::FileSource file(filePath, true);
        privateKey.Load(file);
    }

    std::string encrypt(const std::string& data) const {
        CryptoPP::AutoSeededRandomPool rng;

        std::string cipher;
        CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        CryptoPP::StringSource ss(data, true, 
            new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::StringSink(cipher))
        );
        return cipher;
    }

    std::string decrypt(const std::string& cipher) const {
        CryptoPP::AutoSeededRandomPool rng;

        std::string recovered;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        CryptoPP::StringSource ss(cipher, true, 
            new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(recovered))
        );
        return recovered;
    }
};

int main() {
    try {
        KeyValueStore store;
        PutOption option;

        // 测试不加密存储
        std::string key1 = "test1.txt";
        std::string value1 = "This is a test string.";
        option.encrypt = false;
        store.put(key1, value1, option);

        std::string result1;
        store.get(key1, result1);
        std::cout << "Retrieved value (not encrypted): " << result1 << std::endl;

        // 测试加密存储
        std::string key2 = "test2.txt";
        std::string value2 = "This is another test string.";
        option.encrypt = true;
        store.put(key2, value2, option);

        std::string result2;
        store.get(key2, result2);
        std::cout << "Retrieved value (encrypted): " << result2 << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

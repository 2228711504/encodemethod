#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <cstdlib>
#include <chrono>
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

        int numFiles = 100; // 处理的文件数量

        // 创建测试目录
        std::string correctnessDir = "correctness_tests";
        std::string performanceDir = "performance_tests";
        std::filesystem::create_directory(correctnessDir);
        std::filesystem::create_directory(performanceDir);

        // 正确性验证（加密）
        bool allCorrect = true;
        for (int i = 0; i < numFiles; ++i) {
            std::string key = correctnessDir + "/correct_enc" + std::to_string(i) + ".txt";
            std::string value(214, 'A');  // 214B的测试数据
            option.encrypt = true;
            store.put(key, value, option);

            std::string result;
            store.get(key, result);

            if (result != value) {
                std::cerr << "Data mismatch for file (encrypted): " << key << std::endl;
                allCorrect = false;
            }
        }

        // 正确性验证（不加密）
        for (int i = 0; i < numFiles; ++i) {
            std::string key = correctnessDir + "/correct_plain" + std::to_string(i) + ".txt";
            std::string value(214, 'B');  // 214B的测试数据
            option.encrypt = false;
            store.put(key, value, option);

            std::string result;
            store.get(key, result);

            if (result != value) {
                std::cerr << "Data mismatch for file (plain): " << key << std::endl;
                allCorrect = false;
            }
        }

        if (allCorrect) {
            std::cout << "All files were decrypted correctly." << std::endl;
        } else {
            std::cout << "Some files were not decrypted correctly." << std::endl;
            return 1; // 如果文件不正确，不继续性能测试
        }

        // 性能测试（加密）
        size_t totalBytesEncrypted = 0;
        size_t totalBytesDecrypted = 0;
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < numFiles; ++i) {
            std::string key = performanceDir + "/perf_enc" + std::to_string(i) + ".txt";
            std::string value(214, 'A');
            option.encrypt = true;
            store.put(key, value, option);
            totalBytesEncrypted += value.size();
        }

        auto mid = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < numFiles; ++i) {
            std::string key = performanceDir + "/perf_enc" + std::to_string(i) + ".txt";
            std::string result;
            store.get(key, result);
            totalBytesDecrypted += result.size();
        }

        auto end = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> encryptTime = mid - start;
        std::chrono::duration<double> decryptTime = end - mid;

        std::cout << "Processed " << numFiles << " encrypted files." << std::endl;
        std::cout << "Get speed (encrypted): " << totalBytesEncrypted / encryptTime.count() / 1024.0 << " KB/s" << std::endl;
        std::cout << "Put speed (encrypted): " << totalBytesDecrypted / decryptTime.count() / 1024.0 << " KB/s" << std::endl;

        // 性能测试（不加密）
        totalBytesEncrypted = 0;
        totalBytesDecrypted = 0;
        start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < numFiles; ++i) {
            std::string key = performanceDir + "/perf_plain" + std::to_string(i) + ".txt";
            std::string value(214, 'B');
            option.encrypt = false;
            store.put(key, value, option);
            totalBytesEncrypted += value.size();
        }

        mid = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < numFiles; ++i) {
            std::string key = performanceDir + "/perf_plain" + std::to_string(i) + ".txt";
            std::string result;
            store.get(key, result);
            totalBytesDecrypted += result.size();
        }

        end = std::chrono::high_resolution_clock::now();

        encryptTime = mid - start;
        decryptTime = end - mid;

        std::cout << "Processed " << numFiles << " plain files." << std::endl;
        std::cout << "Get speed (normal): " << totalBytesEncrypted / encryptTime.count() / 1024.0 << " KB/s" << std::endl;
        std::cout << "Put speed (normal): " << totalBytesDecrypted / decryptTime.count() / 1024.0 << " KB/s" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

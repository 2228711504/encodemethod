#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <cstdlib>  // For std::getenv
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

struct PutOption {
    bool encrypt = false;  // 是否加密存储
};

class KeyValueStore {
public:
    KeyValueStore() {
        // 从环境变量读取 key 和 iv
        const char* key_env = std::getenv("ENCRYPTION_KEY");
        const char* iv_env = std::getenv("ENCRYPTION_IV");

        if (key_env == nullptr || iv_env == nullptr) {
            throw std::runtime_error("Environment variables ENCRYPTION_KEY or ENCRYPTION_IV not set.");
        }

        // 将密钥和IV转换为二进制形式
        std::string key_str = hexToBytes(key_env);
        std::string iv_str = hexToBytes(iv_env);

        std::cout << "Key length: " << key_str.size() << " bytes" << std::endl;
        std::cout << "IV length: " << iv_str.size() << " bytes" << std::endl;

        if (key_str.size() != CryptoPP::AES::MAX_KEYLENGTH || iv_str.size() != CryptoPP::AES::BLOCKSIZE) {
            throw std::runtime_error("Invalid key or IV size.");
        }

        std::copy(key_str.begin(), key_str.end(), key);
        std::copy(iv_str.begin(), iv_str.end(), iv);
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

        // 检查是否存在加密文件（.enc）
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
    unsigned char key[CryptoPP::AES::MAX_KEYLENGTH];  // 32 bytes for AES-256
    unsigned char iv[CryptoPP::AES::BLOCKSIZE];       // 16 bytes for AES IV

    std::string encrypt(const std::string& data) const {
        std::string cipher;
        CryptoPP::AES::Encryption aesEncryption(key, sizeof(key));
        CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
        CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
        stfEncryptor.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
        stfEncryptor.MessageEnd();

        return cipher;
    }

    std::string decrypt(const std::string& cipher) const {
        std::string decrypted;
        CryptoPP::AES::Decryption aesDecryption(key, sizeof(key));
        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipher.c_str()), cipher.size());
        stfDecryptor.MessageEnd();

        return decrypted;
    }

    std::string hexToBytes(const std::string& hex) const {
        std::string bytes;
        CryptoPP::StringSource ss(hex, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StringSink(bytes)
            )
        );
        return bytes;
    }
};

int main() {
    try {
        KeyValueStore store;
        PutOption option;

        int numFiles = 100; // 处理的文件数量

        // 创建测试目录
        std::string correctnessDir = "correctness_tests_aes";
        std::string performanceDir = "performance_tests_aes";
        std::filesystem::create_directory(correctnessDir);
        std::filesystem::create_directory(performanceDir);

        // 正确性验证（加密）
        bool allCorrect = true;
        for (int i = 0; i < numFiles; ++i) {
            std::string key = correctnessDir + "/correct_enc" + std::to_string(i) + ".txt";
            std::string value(1024, 'A');  // 214B的测试数据
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
        std::cout << "Encryption speed (encrypted): " << totalBytesEncrypted / encryptTime.count() / 1024.0 << " KB/s" << std::endl;
        std::cout << "Decryption speed (encrypted): " << totalBytesDecrypted / decryptTime.count() / 1024.0 << " KB/s" << std::endl;

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
        std::cout << "Encryption speed (plain): " << totalBytesEncrypted / encryptTime.count() / 1024.0 << " KB/s" << std::endl;
        std::cout << "Decryption speed (plain): " << totalBytesDecrypted / decryptTime.count() / 1024.0 << " KB/s" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

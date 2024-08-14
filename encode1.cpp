// # 设置256位密钥（64个十六进制字符）
// export ENCRYPTION_KEY="00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
// # 设置128位IV（32个十六进制字符）
// export ENCRYPTION_IV="AABBCCDDEEFF00112233445566778899"

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

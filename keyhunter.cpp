#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <array>
#include <chrono>
#include <thread>
#include <atomic>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>
using namespace std;
using namespace chrono;

const vector<array<unsigned char, 20>> TARGET_HASHES = {
    {0xa0,0xb0,0xd6,0x0e,0x59,0x91,0x57,0x8e,0xd3,0x7c,0xbd,0xa2,0xb1,0x7d,0x8b,0x2c,0xe2,0x3a,0xb2,0x95},
    {0xd7,0x4d,0xe9,0x5f,0x65,0x79,0x97,0x93,0xf1,0x6b,0x91,0xed,0x8a,0x15,0x21,0x10,0x65,0x2d,0x3e,0xc0},
    {0x12,0xd5,0xa8,0x45,0xf2,0xb2,0x12,0xce,0x0c,0x3b,0xd6,0x5a,0x40,0x35,0x88,0x1d,0x92,0x19,0x09,0x0e},
    {0x14,0xc1,0xed,0x72,0xd0,0x91,0x50,0xb8,0xe5,0xf4,0x9d,0x94,0xd5,0x30,0x70,0xd2,0xc1,0xf1,0xdb,0x36},
    {0xf8,0x75,0x35,0x59,0xcd,0x67,0x30,0x46,0x04,0x4b,0xaf,0x06,0x72,0x5c,0x7a,0x94,0xbc,0xb8,0xa5,0x92},
    {0xe3,0x68,0x43,0xf1,0xd4,0x98,0xea,0xf6,0xe6,0x28,0x75,0x36,0x23,0x25,0x51,0xef,0xe8,0xf5,0x71,0x47}
};

vector<unsigned char> sha256(const vector<unsigned char>& data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

vector<unsigned char> ripemd160(const vector<unsigned char>& data) {
    vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), hash.data());
    return hash;
}

string to_hex(const vector<unsigned char>& data) {
    ostringstream oss;
    for (unsigned char c : data) {
        oss << hex << setw(2) << setfill('0') << (int)c;
    }
    return oss.str();
}

vector<unsigned char> hex_to_bytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

void worker(secp256k1_context* ctx, atomic<uint64_t>& iterations, ofstream& found_file, steady_clock::time_point start_time, int duration_seconds, atomic<bool>& forced_once) {
    while (duration_cast<seconds>(steady_clock::now() - start_time).count() < duration_seconds) {
        vector<unsigned char> private_key(32);

        if (!forced_once.exchange(true)) {
            private_key = hex_to_bytes("1FCBBE66C345DEBDC2A77891AC4E6D8A97AA73884CABD6159DB32FF881A1D086");
        } else {
            RAND_bytes(private_key.data(), private_key.size());
        }

        secp256k1_pubkey raw_pubkey;
        if (secp256k1_ec_pubkey_create(ctx, &raw_pubkey, private_key.data())) {
            unsigned char pubkey_serialized[65];
            size_t pubkeylen = 65;
            secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkeylen, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

            vector<unsigned char> pubkey_vec(pubkey_serialized, pubkey_serialized + pubkeylen);
            vector<unsigned char> hash160 = ripemd160(sha256(pubkey_vec));

            for (const auto& target : TARGET_HASHES) {
                if (equal(target.begin(), target.end(), hash160.begin())) {
                    string hex_priv = to_hex(private_key);
                    cout << "\nChave encontrada! Private Key: " << hex_priv << endl;
                    found_file << hex_priv << endl;
                }
            }
        }

        ++iterations;
    }
}

int main() {
    ofstream found_file("found_keys.txt", ios::app);
    if (!found_file.is_open()) {
        cerr << "Erro ao abrir 'found_keys.txt' para escrita." << endl;
        return 1;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    auto start_time = steady_clock::now();
    const long long duration_seconds = 17LL * 3600LL; // 17 horas em segundos

    atomic<uint64_t> iterations(0);
    atomic<bool> forced_once(false);
    unsigned int num_threads = thread::hardware_concurrency();
    vector<thread> threads;

    for (unsigned int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker, ctx, ref(iterations), ref(found_file), start_time, duration_seconds, ref(forced_once));
    }

    while (duration_cast<seconds>(steady_clock::now() - start_time).count() < duration_seconds) {
        auto now = steady_clock::now();
        double elapsed = duration_cast<milliseconds>(now - start_time).count() / 1000.0;
        double percent = elapsed / duration_seconds;
        int time_left = duration_seconds - static_cast<int>(elapsed);

        cout << "Iteracoes: " << iterations.load() << " [";
        int width = 50;
        int pos = percent * width;
        for (int i = 0; i < width; ++i) {
            if (i < pos) cout << "=";
            else if (i == pos) cout << ">";
            else cout << " ";
        }
        cout << "] " << fixed << setprecision(1) << (percent * 100.0) << "% ";
        cout << "Tempo restante: " << time_left << "s\r";
        cout.flush();

        this_thread::sleep_for(milliseconds(100));
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    secp256k1_context_destroy(ctx);
    found_file.close();

    cout << "\n\nTempo esgotado! Total de iterações: " << iterations.load() << endl;

    return 0;
}

//export PATH=/mingw64/bin:$PATH
//g++ -O3 -march=native -I /mingw64/include -I /mingw64/include/openssl -L /mingw64/lib keyhunter.cpp -o keyhunter.exe -lssl -lcrypto -lsecp256k1 -lpthread
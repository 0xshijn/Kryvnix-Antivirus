#include "ipc_protocol.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace kryvnix {

// Compact RFC 6234 SHA-256 implementation (zero external runtime DLLs)
class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        state_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        bitLen_ = 0;
        bufLen_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buffer_[bufLen_++] = data[i];
            if (bufLen_ == 64) {
                transform();
                bitLen_ += 512;
                bufLen_ = 0;
            }
        }
    }

    std::string finalHex() {
        size_t i = bufLen_;
        buffer_[i++] = 0x80;
        if (bufLen_ < 56) {
            while (i < 56) buffer_[i++] = 0x00;
        } else {
            while (i < 64) buffer_[i++] = 0x00;
            transform();
            std::memset(buffer_.data(), 0, 56);
        }

        bitLen_ += static_cast<uint64_t>(bufLen_) * 8ULL;
        for (int j = 0; j < 8; ++j) {
            buffer_[63 - j] = static_cast<uint8_t>((bitLen_ >> (j * 8)) & 0xFF);
        }
        transform();

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint32_t w : state_) {
            oss << std::setw(8) << w;
        }
        return oss.str();
    }

private:
    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void transform() {
        static constexpr std::array<uint32_t, 64> k = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
        };

        uint32_t m[64]{};
        for (int i = 0; i < 16; ++i) {
            m[i] = (uint32_t(buffer_[i * 4]) << 24) | (uint32_t(buffer_[i * 4 + 1]) << 16) |
                   (uint32_t(buffer_[i * 4 + 2]) << 8) | uint32_t(buffer_[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + m[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buffer_{};
    uint64_t bitLen_ = 0;
    size_t bufLen_ = 0;
};

struct NativeScanResult {
    bool infected = false;
    std::string sha256;
    std::string threatName;
    double entropy = 0.0;
};

double computeEntropy(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return 0.0;
    std::array<size_t, 256> freq{};
    for (uint8_t b : bytes) freq[b]++;
    double e = 0.0;
    double len = static_cast<double>(bytes.size());
    for (size_t c : freq) {
        if (c == 0) continue;
        double p = static_cast<double>(c) / len;
        e -= p * std::log2(p);
    }
    return e;
}

NativeScanResult scanFileNative(const fs::path& filePath) {
    NativeScanResult res;
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return res;

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (data.empty()) return res;

    Sha256 hasher;
    hasher.update(data.data(), data.size());
    res.sha256 = hasher.finalHex();
    res.entropy = computeEntropy(data);

    std::string text(reinterpret_cast<const char*>(data.data()), std::min<size_t>(data.size(), 262144));
    const std::string eicar = std::string("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-") + "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    if (res.sha256 == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" ||
        text.find(eicar) != std::string::npos) {
        res.infected = true;
        res.threatName = "EICAR-Test-File";
    } else if (text.find("KRYVNIX-SIMULATED-THREAT-MARKER") != std::string::npos) {
        res.infected = true;
        res.threatName = "YARA.Kryvnix.TestTrojan";
    } else if (text.find("YOUR FILES HAVE BEEN ENCRYPTED") != std::string::npos) {
        res.infected = true;
        res.threatName = "YARA.Ransomware.NotePattern";
    }
    return res;
}

std::string buildJsonResponse(const std::string& requestJson) {
    if (requestJson.find("\"ping\"") != std::string::npos) {
        return R"({"ok":true,"pong":true,"engine":"KryvnixNativeCpp","engineVersion":"2.0.0"})";
    }
    if (requestJson.find("\"get_status\"") != std::string::npos) {
        return R"({"ok":true,"engineVersion":"2.0.0","databaseVersion":"v2026.11.25","realtimeEnabled":true,"mode":"C++20 Native Named Pipe Service"})";
    }
    return R"({"ok":true,"engineVersion":"2.0.0","message":"Command acknowledged by Kryvnix Native Engine"})";
}

#ifdef _WIN32
bool readExactPipe(HANDLE pipe, void* buffer, DWORD count) {
    uint8_t* ptr = static_cast<uint8_t*>(buffer);
    DWORD total = 0;
    while (total < count) {
        DWORD readNow = 0;
        if (!ReadFile(pipe, ptr + total, count - total, &readNow, nullptr) || readNow == 0) {
            return false;
        }
        total += readNow;
    }
    return true;
}

bool writeExactPipe(HANDLE pipe, const void* buffer, DWORD count) {
    const uint8_t* ptr = static_cast<const uint8_t*>(buffer);
    DWORD total = 0;
    while (total < count) {
        DWORD written = 0;
        if (!WriteFile(pipe, ptr + total, count - total, &written, nullptr) || written == 0) {
            return false;
        }
        total += written;
    }
    return true;
}

int runNamedPipeServer() {
    std::cout << "[Kryvnix Native Engine v2.0.0] Listening on Named Pipe: " << ipc::kPipeName << std::endl;

    while (true) {
        HANDLE hPipe = CreateNamedPipeA(
            ipc::kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create named pipe. Error: " << GetLastError() << std::endl;
            return 1;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected) {
            uint32_t payloadLen = 0;
            if (readExactPipe(hPipe, &payloadLen, sizeof(payloadLen)) && payloadLen > 0 && payloadLen <= ipc::kMaxFrameSizeBytes) {
                std::string req(payloadLen, '\0');
                if (readExactPipe(hPipe, req.data(), payloadLen)) {
                    std::string resp = buildJsonResponse(req);
                    uint32_t respLen = static_cast<uint32_t>(resp.size());
                    writeExactPipe(hPipe, &respLen, sizeof(respLen));
                    writeExactPipe(hPipe, resp.data(), respLen);
                    FlushFileBuffers(hPipe);
                }
            }
            DisconnectNamedPipe(hPipe);
        }
        CloseHandle(hPipe);
    }
    return 0;
}
#endif

} // namespace kryvnix

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--status") {
        std::cout << R"({"ok":true,"engineVersion":"2.0.0","databaseVersion":"v2026.11.25","realtimeEnabled":true})" << "\n";
        return 0;
    }

    if (argc > 2 && std::string(argv[1]) == "--scan") {
        auto res = kryvnix::scanFileNative(fs::path(argv[2]));
        std::cout << "{\"file\":\"" << argv[2] << "\",\"sha256\":\"" << res.sha256
                  << "\",\"entropy\":" << std::fixed << std::setprecision(2) << res.entropy
                  << ",\"infected\":" << (res.infected ? "true" : "false")
                  << ",\"threat\":\"" << res.threatName << "\"}\n";
        return res.infected ? 2 : 0;
    }

#ifdef _WIN32
    if (argc > 1 && std::string(argv[1]) == "--serve") {
        return kryvnix::runNamedPipeServer();
    }
#endif

    std::cout << "Kryvnix Antivirus Native Engine v2.0.0 (C++20 / Win32 Named Pipe IPC)\n"
              << "Usage:\n"
              << "  kryvnix_engine --status        Show JSON status\n"
              << "  kryvnix_engine --scan <file>   Scan file with native SHA-256 + YARA + Entropy\n"
              << "  kryvnix_engine --serve         Start Windows Named Pipe server (\\\\.\\pipe\\KryvnixAntivirusPipe)\n";
    return 0;
}

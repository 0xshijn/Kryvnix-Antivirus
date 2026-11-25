#include "ipc_protocol.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::cout << "Kryvnix Antivirus Native Engine v" << kryvnix::ipc::EngineStatus{}.engineVersion << "\n";
    std::cout << "IPC Pipe Endpoint: " << kryvnix::ipc::kPipeName << "\n";

    if (argc > 1 && std::string(argv[1]) == "--status") {
        std::cout << "{\"ok\":true,\"engineVersion\":\"1.0.0\",\"databaseVersion\":\"v2025.01.15\",\"realtimeEnabled\":true}\n";
        return 0;
    }

    std::cout << "Ready for Phase 02-04 engine integration (libyara, OpenSSL SHA-256, Windows Service).\n";
    return 0;
}

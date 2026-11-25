#pragma once

#include <cstdint>
#include <string>

namespace kryvnix::ipc {

inline constexpr const char* kPipeName = R"(\\.\pipe\KryvnixAntivirusPipe)";
inline constexpr uint32_t kProtocolVersion = 1;
inline constexpr uint32_t kMaxFrameSizeBytes = 4 * 1024 * 1024;

// Message commands shared with KryvnixAntivirus.Desktop (NamedPipeEngineClient)
inline constexpr const char* kCmdPing = "ping";
inline constexpr const char* kCmdGetStatus = "get_status";
inline constexpr const char* kCmdStartScan = "start_scan";
inline constexpr const char* kCmdCancelScan = "cancel_scan";
inline constexpr const char* kCmdSetRealtime = "set_realtime";
inline constexpr const char* kCmdQuarantine = "quarantine_file";
inline constexpr const char* kCmdRestore = "restore_file";

struct EngineStatus {
    std::string engineVersion = "1.0.0";
    std::string databaseVersion = "v2025.01.15";
    bool realtimeEnabled = true;
    bool fileMonitorEnabled = true;
    bool processMonitorEnabled = true;
    bool networkShieldEnabled = true;
    bool behaviorMonitorEnabled = true;
};

} // namespace kryvnix::ipc

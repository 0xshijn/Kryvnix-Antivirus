using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using KryvnixAntivirus.Desktop.Models;

namespace KryvnixAntivirus.Desktop.Services;

public interface IEngineIpcClient
{
    Task<EngineStatusSnapshot> CheckStatusAsync(string pipeName, bool simulateUnavailable = false, CancellationToken ct = default);
    Task<JsonDocument?> SendRequestAsync(string pipeName, object requestPayload, int timeoutMs = 1500, CancellationToken ct = default);
}

public sealed class NamedPipeEngineClient : IEngineIpcClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<EngineStatusSnapshot> CheckStatusAsync(string pipeName, bool simulateUnavailable = false, CancellationToken ct = default)
    {
        if (simulateUnavailable)
        {
            return new EngineStatusSnapshot
            {
                IsNativeServiceConnected = false,
                IsEngineOperational = false,
                EngineVersion = "1.0.0",
                CheckedAt = DateTime.Now
            };
        }

        try
        {
            using var doc = await SendRequestAsync(pipeName, new { command = "get_status", protocolVersion = 1 }, 600, ct);
            if (doc is not null && doc.RootElement.TryGetProperty("ok", out var okProp) && okProp.GetBoolean())
            {
                return new EngineStatusSnapshot
                {
                    IsNativeServiceConnected = true,
                    IsEngineOperational = true,
                    EngineVersion = doc.RootElement.TryGetProperty("engineVersion", out var v) ? v.GetString() ?? "1.0.0" : "1.0.0",
                    DatabaseVersion = doc.RootElement.TryGetProperty("databaseVersion", out var dbv) ? dbv.GetString() ?? "v2025.01.15" : "v2025.01.15",
                    CheckedAt = DateTime.Now
                };
            }
        }
        catch
        {
            // Native Windows service not installed/started yet; fallback to built-in hybrid local engine
        }

        return new EngineStatusSnapshot
        {
            IsNativeServiceConnected = false,
            IsEngineOperational = true,
            EngineVersion = "1.0.0",
            CheckedAt = DateTime.Now
        };
    }

    public async Task<JsonDocument?> SendRequestAsync(string pipeName, object requestPayload, int timeoutMs = 1500, CancellationToken ct = default)
    {
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);

        await client.ConnectAsync(timeoutCts.Token);

        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(requestPayload, JsonOptions);
        var lengthPrefix = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)payloadBytes.Length);

        await client.WriteAsync(lengthPrefix, timeoutCts.Token);
        await client.WriteAsync(payloadBytes, timeoutCts.Token);
        await client.FlushAsync(timeoutCts.Token);

        var respLenBuf = new byte[4];
        await ReadExactAsync(client, respLenBuf, timeoutCts.Token);
        var respLen = BinaryPrimitives.ReadUInt32LittleEndian(respLenBuf);
        if (respLen == 0 || respLen > 4 * 1024 * 1024)
        {
            return null;
        }

        var respBuf = new byte[respLen];
        await ReadExactAsync(client, respBuf, timeoutCts.Token);
        return JsonDocument.Parse(Encoding.UTF8.GetString(respBuf));
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct);
            if (read == 0) throw new EndOfStreamException("Named pipe closed unexpectedly.");
            offset += read;
        }
    }
}

using System.Buffers.Binary;
using System.Net.Sockets;

namespace RDRF.Server;

public static class ProtocolHandler
{
    private const int HeaderSize = 13; // 1 cmd + 4 seq + 4 dataLen + 4 pathLen
    private static readonly byte[] VersionBytes = System.Text.Encoding.UTF8.GetBytes("RDRF/1.0");

    public static async Task HandleAsync(NetworkStream stream, CancellationToken ct)
    {
        var headerBuf = new byte[HeaderSize];
        var buffer = new byte[65536];

        while (!ct.IsCancellationRequested)
        {
            // Read frame header
            if (!await ReadExactAsync(stream, headerBuf, 0, HeaderSize, ct).ConfigureAwait(false))
                break;

            byte cmd = headerBuf[0];
            uint seqNo = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(1, 4));
            uint dataLen = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(5, 4));
            uint pathLen = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(9, 4));

            // Read frame data (may span multiple reads)
            byte[] data = dataLen > 0 ? await ReadExactDataAsync(stream, dataLen, ct).ConfigureAwait(false) : [];
            string path = pathLen > 0 ? System.Text.Encoding.UTF8.GetString(data, 0, (int)pathLen) : "";
            byte[] payload = dataLen > pathLen ? data[(int)pathLen..] : [];

            byte[]? response = cmd switch
            {
                0x01 => HandlePut(path, payload, seqNo),
                0x02 => HandleGet(path, seqNo),
                0x03 => HandleDelete(path, seqNo),
                0x04 => HandleExists(path, seqNo),
                0x05 => HandleList(path, seqNo),
                0x06 => HandlePing(seqNo),
                0x07 => HandleResume(path, payload, seqNo),
                _ => BuildError(seqNo, $"Unknown command: 0x{cmd:X2}")
            };

            if (response != null)
                await stream.WriteAsync(response.AsMemory(0, response.Length), ct).ConfigureAwait(false);
        }
    }

    private static byte[]? HandleGet(string name, uint seq)
    {
        var data = FragmentStore.ReadFragment(name);
        if (data == null) return BuildError(seq, "Not found");
        return BuildResponse(0x02, seq, data);
    }

    private static byte[]? HandlePut(string name, byte[] data, uint seq)
    {
        if (data.Length == 0) return BuildError(seq, "Empty PUT");
        FragmentStore.WriteFragment(name, data);
        return BuildStatus(0x01, seq, 0);
    }

    private static byte[]? HandleDelete(string name, uint seq)
    {
        FragmentStore.Delete(name);
        return BuildStatus(0x03, seq, 0);
    }

    private static byte[]? HandleExists(string name, uint seq)
    {
        if (FragmentStore.Exists(name))
        {
            var file = new FileInfo(Path.Combine(FragmentStore.StoragePath, name));
            byte[] resp = new byte[HeaderSize + 9]; // found(1) + size(8)
            WriteHeader(resp, 0x04, seq, 9, 0);
            resp[HeaderSize] = 0x01;
            BinaryPrimitives.WriteInt64LittleEndian(resp.AsSpan(HeaderSize + 1, 8), file.Length);
            return resp;
        }
        return BuildStatus(0x04, seq, 1);
    }

    private static byte[]? HandleList(string prefix, uint seq)
    {
        var indices = FragmentStore.ListIndices(prefix);
        int dataLen = 4 + indices.Count * 4;
        byte[] resp = new byte[HeaderSize + dataLen];
        WriteHeader(resp, 0x05, seq, (uint)dataLen, 0);
        BinaryPrimitives.WriteInt32LittleEndian(resp.AsSpan(HeaderSize, 4), indices.Count);
        for (int i = 0; i < indices.Count; i++)
            BinaryPrimitives.WriteInt32LittleEndian(resp.AsSpan(HeaderSize + 4 + i * 4, 4), indices[i]);
        return resp;
    }

    private static byte[]? HandlePing(uint seq)
    {
        return BuildResponse(0x06, seq, VersionBytes);
    }

    private static byte[]? HandleResume(string name, byte[] data, uint seq)
    {
        long offset = data.Length >= 8 ? BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(0, 8)) : 0;
        byte[] fragData = data.Length > 8 ? data[8..] : [];

        using var partStream = FragmentStore.OpenResumeStream(name, offset);
        partStream.Write(fragData, 0, fragData.Length);
        return BuildStatus(0x07, seq, 0);
    }

    // --- Helpers ---

    private static byte[] BuildResponse(byte cmd, uint seq, byte[] data)
    {
        byte[] resp = new byte[HeaderSize + data.Length];
        WriteHeader(resp, cmd, seq, (uint)data.Length, 0);
        Array.Copy(data, 0, resp, HeaderSize, data.Length);
        return resp;
    }

    private static byte[] BuildStatus(byte cmd, uint seq, byte status)
    {
        byte[] resp = new byte[HeaderSize + 1];
        WriteHeader(resp, cmd, seq, 1, 0);
        resp[HeaderSize] = status;
        return resp;
    }

    private static byte[] BuildError(uint seq, string msg)
    {
        byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(msg);
        byte[] resp = new byte[HeaderSize + msgBytes.Length];
        WriteHeader(resp, 0xFF, seq, (uint)msgBytes.Length, 0);
        Array.Copy(msgBytes, 0, resp, HeaderSize, msgBytes.Length);
        return resp;
    }

    private static void WriteHeader(byte[] buf, byte cmd, uint seq, uint dataLen, uint pathLen)
    {
        buf[0] = cmd;
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(1, 4), seq);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(5, 4), dataLen);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(9, 4), pathLen);
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buf, int offset, int count, CancellationToken ct)
    {
        int read = 0;
        while (read < count)
        {
            int n = await stream.ReadAsync(buf.AsMemory(offset + read, count - read), ct).ConfigureAwait(false);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    private static async Task<byte[]> ReadExactDataAsync(NetworkStream stream, uint count, CancellationToken ct)
    {
        byte[] data = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await stream.ReadAsync(data.AsMemory(read, (int)(count - read)), ct).ConfigureAwait(false);
            if (n == 0) break;
            read += n;
        }
        if (read < count) Array.Resize(ref data, read);
        return data;
    }
}

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net.Sockets;

namespace RDRF.Core.DSAA;

public class RdrfNativeBackend : IStorageBackend
{
    private readonly string _host;
    private readonly int _port;
    private readonly ConcurrentBag<TcpConnection> _pool = new();
    private uint _nextSeq;

    public string Name { get; }

    public RdrfNativeBackend(string name, string host, int port)
    {
        Name = name;
        _host = host;
        _port = port;
    }

    public async Task<Stream> OpenReadAsync(string path)
    {
        var conn = await RentAsync();
        try
        {
            byte[] request = BuildFrame(0x02, path, []);
            await conn.Stream.WriteAsync(request).ConfigureAwait(false);
            var (cmd, _, data) = await ReadFrameAsync(conn.Stream);
            if (cmd == 0xFF) throw new IOException($"Server error: {System.Text.Encoding.UTF8.GetString(data)}");
            if (cmd != 0x02 || data == null) throw new IOException("Invalid GET response");
            _pool.Add(conn);
            return new MemoryStream(data);
        }
        catch { conn.Dispose(); throw; }
    }

    public async Task<Stream> OpenWriteAsync(string path, long fileSize, IProgress<StorageProgress>? progress = null)
    {
        var conn = await RentAsync();
        return new RdrfWriteStream(conn, this, path);
    }

    public async Task DeleteAsync(string path)
    {
        var conn = await RentAsync();
        try
        {
            byte[] request = BuildFrame(0x03, path, []);
            await conn.Stream.WriteAsync(request).ConfigureAwait(false);
            var (cmd, _, _) = await ReadFrameAsync(conn.Stream);
            _pool.Add(conn);
        }
        catch { conn.Dispose(); throw; }
    }

    public async Task<bool> ExistsAsync(string path)
    {
        var conn = await RentAsync();
        try
        {
            byte[] request = BuildFrame(0x04, path, []);
            await conn.Stream.WriteAsync(request).ConfigureAwait(false);
            var (cmd, _, data) = await ReadFrameAsync(conn.Stream);
            _pool.Add(conn);
            return cmd == 0x04 && data != null && data.Length >= 9 && data[0] == 1;
        }
        catch { conn.Dispose(); return false; }
    }

    public async Task<bool> PingAsync()
    {
        var conn = await RentAsync();
        try
        {
            byte[] request = BuildFrame(0x06, "", []);
            await conn.Stream.WriteAsync(request).ConfigureAwait(false);
            var (cmd, _, _) = await ReadFrameAsync(conn.Stream);
            _pool.Add(conn);
            return cmd == 0x06;
        }
        catch { conn.Dispose(); return false; }
    }

    internal void Return(TcpConnection conn) => _pool.Add(conn);

    internal byte[] BuildFrame(byte cmd, string path, byte[] data)
    {
        byte[] pathBytes = System.Text.Encoding.UTF8.GetBytes(path);
        uint dataLen = (uint)(pathBytes.Length + data.Length);
        uint seq = Interlocked.Increment(ref _nextSeq);
        byte[] frame = new byte[13 + dataLen];
        frame[0] = cmd;
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(1, 4), seq);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(5, 4), dataLen);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(9, 4), (uint)pathBytes.Length);
        Array.Copy(pathBytes, 0, frame, 13, pathBytes.Length);
        if (data.Length > 0) Array.Copy(data, 0, frame, 13 + pathBytes.Length, data.Length);
        return frame;
    }

    private static async Task<(byte cmd, uint seq, byte[]? data)> ReadFrameAsync(NetworkStream stream)
    {
        byte[] hdr = new byte[13];
        await ReadExactAsync(stream, hdr, 13);
        byte cmd = hdr[0];
        uint seq = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(1, 4));
        uint dataLen = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(5, 4));
        if (dataLen == 0) return (cmd, seq, null);
        byte[] data = new byte[dataLen];
        await ReadExactAsync(stream, data, (int)dataLen);
        return (cmd, seq, data);
    }

    private static async Task ReadExactAsync(NetworkStream s, byte[] buf, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(read, count - read)).ConfigureAwait(false);
            if (n == 0) throw new IOException("Connection closed");
            read += n;
        }
    }

    private async Task<TcpConnection> RentAsync()
    {
        if (_pool.TryTake(out var conn) && conn.Stream.Socket.Connected)
            return conn;
        conn?.Dispose();
        var client = new TcpClient();
        await client.ConnectAsync(_host, _port).ConfigureAwait(false);
        return new TcpConnection(client, client.GetStream());
    }

    internal class TcpConnection : IDisposable
    {
        public TcpClient Client;
        public NetworkStream Stream;
        public TcpConnection(TcpClient c, NetworkStream s) { Client = c; Stream = s; }
        public void Dispose() { Stream?.Dispose(); Client?.Dispose(); }
    }

    // Write stream: builds frame per Write call for chunked upload
    internal class RdrfWriteStream : Stream
    {
        private readonly TcpConnection _conn;
        private readonly RdrfNativeBackend _backend;
        private readonly string _path;
        private long _written;
        public RdrfWriteStream(TcpConnection conn, RdrfNativeBackend backend, string path)
        { _conn = conn; _backend = backend; _path = path; }

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte cmd = _written == 0 ? (byte)0x01 : (byte)0x07;
            byte[] offsetBytes = cmd == 0x07 ? BitConverter.GetBytes(_written) : [];
            byte[] data = new byte[offsetBytes.Length + count];
            if (offsetBytes.Length > 0) Array.Copy(offsetBytes, data, 8);
            Array.Copy(buffer, offset, data, offsetBytes.Length, count);
            byte[] frame = _backend.BuildFrame(cmd, _path, data);
            _conn.Stream.Write(frame, 0, frame.Length);
            // Read response to keep stream clean for next pooled use
            try
            {
                byte[] hdr = new byte[13];
                _conn.Stream.ReadExactly(hdr, 0, 13);
                uint dataLen = BinaryPrimitives.ReadUInt32LittleEndian(hdr.AsSpan(5, 4));
                if (dataLen > 0) _conn.Stream.ReadExactly(new byte[dataLen]);
            }
            catch { /* best-effort — connection will be discarded on error */ }
            _written += count;
        }

        public override void Flush() => _conn.Stream.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _written;
        public override long Position { get => _written; set => throw new NotSupportedException(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _backend.Return(_conn);
        }
    }
}

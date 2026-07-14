using RDRF.Core.DSAA.Abi;

namespace RDRF.Core.DSAA.NativePlugin;

internal sealed class NativeReadStream : Stream
{
    private readonly IntPtr _stream;
    private readonly DsaaStorageAbi.StreamReadDelegate _read;
    private readonly DsaaStorageAbi.StreamCloseDelegate _close;
    private bool _disposed;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public NativeReadStream(IntPtr stream,
        DsaaStorageAbi.StreamReadDelegate read,
        DsaaStorageAbi.StreamCloseDelegate close)
    {
        _stream = stream;
        _read = read;
        _close = close;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(NativeReadStream));
        if (offset != 0) throw new NotSupportedException("Non-zero offset not supported");
        long result = _read(_stream, buffer, count);
        if (result < 0) throw new IOException("Native read failed");
        return (int)result;
    }

    public override void Flush() { }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _close(_stream);
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}

internal sealed class NativeWriteStream : Stream
{
    private readonly IntPtr _stream;
    private readonly DsaaStorageAbi.StreamWriteDelegate _write;
    private readonly DsaaStorageAbi.StreamCloseDelegate _close;
    private bool _disposed;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public NativeWriteStream(IntPtr stream,
        DsaaStorageAbi.StreamWriteDelegate write,
        DsaaStorageAbi.StreamCloseDelegate close)
    {
        _stream = stream;
        _write = write;
        _close = close;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(NativeWriteStream));
        if (offset != 0) throw new NotSupportedException("Non-zero offset not supported");
        long result = _write(_stream, buffer, count);
        if (result < 0) throw new IOException("Native write failed");
    }

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _close(_stream);
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}

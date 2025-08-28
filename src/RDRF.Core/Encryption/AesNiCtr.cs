using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using SCryptography = System.Security.Cryptography;

namespace RDRF.Core.Encryption;

public static class AesNiCtr
{
    public static bool IsSupported => Aes.IsSupported;

    public static byte[] CtrCrypt(byte[] data, byte[] aesKey, byte[] nonce)
    {
        byte[] output = new byte[data.Length];
        var rk = ExpandKey256(aesKey);
        var counter = BuildCounter(nonce);

        if (Aes.IsSupported)
            CtrCryptCoreAesNi(data.AsSpan(), output.AsSpan(), rk, ref counter);
        else
            CtrCryptCoreFallback(data, output, aesKey, nonce);

        return output;
    }

    public static void CtrCryptStream(Stream input, Stream output, byte[] aesKey, byte[] nonce, int bufferSize = 81920)
    {
        var rk = ExpandKey256(aesKey);
        var counter = BuildCounter(nonce);
        byte[] buffer = new byte[bufferSize];

        while (true)
        {
            int bytesRead = input.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0) break;

            if (Aes.IsSupported)
            {
                int offset = 0;
                while (offset < bytesRead)
                {
                    int chunk = Math.Min(16, bytesRead - offset);
                    if (chunk == 16)
                    {
                        var keyStream = AesEncryptBlock(counter, rk);
                        ref byte bufRef = ref MemoryMarshal.GetReference(buffer.AsSpan(offset));
                        var src = Vector128.LoadUnsafe(ref bufRef);
                        Vector128.Xor(keyStream, src).CopyTo(buffer.AsSpan(offset));
                        counter = IncrementCounter(counter);
                    }
                    else
                    {
                        Span<byte> ks = stackalloc byte[16];
                        AesEncryptBlock(counter, rk).CopyTo(ks);
                        for (int j = 0; j < chunk; j++)
                            buffer[offset + j] ^= ks[j];
                        counter = IncrementCounter(counter);
                    }
                    offset += chunk;
                }
            }
            else
            {
                int blockCount = (bytesRead + 15) / 16;
                var counters = new byte[blockCount * 16];
                var keystream = new byte[blockCount * 16];
                Span<byte> ctr = stackalloc byte[16];
                counter.CopyTo(ctr);

                for (int i = 0; i < blockCount; i++)
                {
                    ctr.CopyTo(counters.AsSpan(i * 16, 16));
                    for (int j = 15; j >= 0; j--)
                        if (++ctr[j] != 0) break;
                }

                using var aes = SCryptography.Aes.Create();
                aes.Key = aesKey;
                aes.Mode = SCryptography.CipherMode.ECB;
                aes.Padding = SCryptography.PaddingMode.None;
                using var enc = aes.CreateEncryptor();
                enc.TransformBlock(counters, 0, counters.Length, keystream, 0);

                for (int i = 0; i < bytesRead; i++)
                    buffer[i] ^= keystream[i];
            }

            output.Write(buffer, 0, bytesRead);
        }
    }

    // ── Key Expansion (AES-256, 15 round keys) ──

    private static readonly byte[] Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    private static Vector128<byte>[] ExpandKey256(byte[] key)
    {
        var rk = new Vector128<byte>[15];
        rk[0] = Vector128.LoadUnsafe(ref key[0]);
        rk[1] = Vector128.LoadUnsafe(ref key[16]);

        for (int i = 2; i < 15; i++)
        {
            if (i % 2 == 0)
            {
                var temp = Aes.KeygenAssist(rk[i - 1], Rcon[i / 2 - 1]);
                rk[i] = Vector128.Xor(rk[i - 2], KeygenShuffle(temp));
            }
            else
            {
                var temp = Aes.KeygenAssist(rk[i - 1], 0);
                rk[i] = Vector128.Xor(rk[i - 2], KeygenShuffle(temp));
            }
        }
        return rk;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> KeygenShuffle(Vector128<byte> temp)
    {
        return Vector128.Shuffle(temp, Vector128.Create((byte)13, 14, 15, 12, 13, 14, 15, 12,
            13, 14, 15, 12, 13, 14, 15, 12));
    }

    // ── Counter ──

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> BuildCounter(byte[] nonce)
    {
        Span<byte> ctr = stackalloc byte[16];
        nonce.AsSpan(0, Math.Min(nonce.Length, 12)).CopyTo(ctr);
        ctr[15] = 1;
        return Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(ctr));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> IncrementCounter(Vector128<byte> ctr)
    {
        var u = ctr.AsUInt32();
        uint lo = BinaryPrimitives.ReverseEndianness(u.GetElement(3));
        lo++;
        return Vector128.Create(u.GetElement(0), u.GetElement(1), u.GetElement(2),
            BinaryPrimitives.ReverseEndianness(lo)).AsByte();
    }

    // ── AES-256 Encrypt Single Block (14 rounds) ──

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> AesEncryptBlock(Vector128<byte> block, Vector128<byte>[] rk)
    {
        var state = Vector128.Xor(block, rk[0]);
        state = Aes.Encrypt(state, rk[1]);
        state = Aes.Encrypt(state, rk[2]);
        state = Aes.Encrypt(state, rk[3]);
        state = Aes.Encrypt(state, rk[4]);
        state = Aes.Encrypt(state, rk[5]);
        state = Aes.Encrypt(state, rk[6]);
        state = Aes.Encrypt(state, rk[7]);
        state = Aes.Encrypt(state, rk[8]);
        state = Aes.Encrypt(state, rk[9]);
        state = Aes.Encrypt(state, rk[10]);
        state = Aes.Encrypt(state, rk[11]);
        state = Aes.Encrypt(state, rk[12]);
        state = Aes.Encrypt(state, rk[13]);
        state = Aes.EncryptLast(state, rk[14]);
        return state;
    }

    // ── Core AES-NI CTR Loop (4-way interleaved) ──

    private static void CtrCryptCoreAesNi(ReadOnlySpan<byte> src, Span<byte> dst,
        Vector128<byte>[] rk, ref Vector128<byte> counter)
    {
        int i = 0;

        for (; i + 64 <= src.Length; i += 64)
        {
            var c0 = counter; counter = IncrementCounter(counter);
            var c1 = counter; counter = IncrementCounter(counter);
            var c2 = counter; counter = IncrementCounter(counter);
            var c3 = counter; counter = IncrementCounter(counter);

            var k0 = AesEncryptBlock(c0, rk);
            var k1 = AesEncryptBlock(c1, rk);
            var k2 = AesEncryptBlock(c2, rk);
            var k3 = AesEncryptBlock(c3, rk);

            ref var s0 = ref MemoryMarshal.GetReference(src.Slice(i));
            Vector128.Xor(k0, Vector128.LoadUnsafe(ref s0)).CopyTo(dst.Slice(i));
            ref var s1 = ref MemoryMarshal.GetReference(src.Slice(i + 16));
            Vector128.Xor(k1, Vector128.LoadUnsafe(ref s1)).CopyTo(dst.Slice(i + 16));
            ref var s2 = ref MemoryMarshal.GetReference(src.Slice(i + 32));
            Vector128.Xor(k2, Vector128.LoadUnsafe(ref s2)).CopyTo(dst.Slice(i + 32));
            ref var s3 = ref MemoryMarshal.GetReference(src.Slice(i + 48));
            Vector128.Xor(k3, Vector128.LoadUnsafe(ref s3)).CopyTo(dst.Slice(i + 48));
        }

        for (; i + 16 <= src.Length; i += 16)
        {
            var keystream = AesEncryptBlock(counter, rk);
            counter = IncrementCounter(counter);
            ref var s = ref MemoryMarshal.GetReference(src.Slice(i));
            Vector128.Xor(keystream, Vector128.LoadUnsafe(ref s)).CopyTo(dst.Slice(i));
        }

        if (i < src.Length)
        {
            var keystream = AesEncryptBlock(counter, rk);
            int remain = src.Length - i;
            for (int j = 0; j < remain; j++)
                dst[i + j] = (byte)(src[i + j] ^ keystream.GetElement(j));
        }
    }

    // ── Fallback (batch TransformBlock) ──

    private static void CtrCryptCoreFallback(byte[] data, byte[] output, byte[] aesKey, byte[] nonce)
    {
        int blockCount = (data.Length + 15) / 16;
        byte[] counters = new byte[blockCount * 16];
        byte[] keystream = new byte[blockCount * 16];

        Span<byte> ctr = stackalloc byte[16];
        nonce.AsSpan(0, Math.Min(nonce.Length, 12)).CopyTo(ctr);
        ctr[15] = 1;

        for (int i = 0; i < blockCount; i++)
        {
            ctr.CopyTo(counters.AsSpan(i * 16, 16));
            for (int j = 15; j >= 0; j--)
                if (++ctr[j] != 0) break;
        }

        using var aes = SCryptography.Aes.Create();
        aes.Key = aesKey;
        aes.Mode = SCryptography.CipherMode.ECB;
        aes.Padding = SCryptography.PaddingMode.None;
        using var encryptor = aes.CreateEncryptor();
        encryptor.TransformBlock(counters, 0, counters.Length, keystream, 0);

        var dSpan = data.AsSpan();
        var kSpan = keystream.AsSpan();
        var oSpan = output.AsSpan();
        for (int i = 0; i < data.Length; i++)
            oSpan[i] = (byte)(dSpan[i] ^ kSpan[i]);
    }
}

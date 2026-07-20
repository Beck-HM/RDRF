using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using SCryptography = System.Security.Cryptography;

namespace RDRF.Core.Encryption;

/// <summary>
/// Hardware-accelerated AES-256-CTR via AES-NI 8-block interleaving.\n/// CTR used instead of GCM to preserve ETN block-level integrity.
/// </summary>

public static class AesNiCtr
{
    public static bool IsSupported => Aes.IsSupported;

    public static byte[] CtrCrypt(byte[] data, byte[] aesKey, byte[] nonce)
    {
        byte[] output = new byte[data.Length];
        CtrCrypt(data.AsSpan(), output.AsSpan(), aesKey, nonce);
        return output;
    }

    internal static void CtrCrypt(ReadOnlySpan<byte> src, Span<byte> dst, byte[] aesKey, byte[] nonce)
    {
        if (src.Length > 68_719_476_736) // 64 GiB = max safe CTR before counter wraps
            throw new ArgumentOutOfRangeException(nameof(src), "Data exceeds 64 GiB CTR safety limit.");

        // GPU path for large payloads (>1MB): massive parallelism from 1000+ CUDA cores
        if (src.Length > 1_048_576 && RDRF.Core.Device.GpuContext.IsAvailable)
        {
            byte[] tmp = src.ToArray();
            if (RDRF.Core.Device.GpuCrypto.EncryptCtrBatch(tmp, aesKey, nonce))
            {
                tmp.CopyTo(dst);
                return;
            }
        }

        var counter = BuildCounter(nonce);
        if (Aes.IsSupported)
        {
            var rk = ExpandKey256(aesKey);
            CtrCryptCoreAesNi(src, dst, rk, ref counter);
        }
        else
        {
            CtrCryptCoreFallback(src, dst, aesKey, nonce);
        }
    }

    public static void CtrCryptStream(Stream input, Stream output, byte[] aesKey, byte[] nonce, int bufferSize = 81920)
    {
        const long MaxCtrBytes = 68_719_476_736; // 64 GiB = max safe CTR before counter wraps
        long totalProcessed = 0;

        if (Aes.IsSupported)
        {
            var rk = ExpandKey256(aesKey);
            var counter = BuildCounter(nonce);
            const int KeyBlockLen = 4096; // 256 AES blocks x 16 bytes
            byte[] buffer = new byte[bufferSize];
            byte[] keyBlockArr = new byte[KeyBlockLen];

            while (true)
            {
                int bytesRead = input.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;

                totalProcessed += bytesRead;
                if (totalProcessed > MaxCtrBytes)
                    throw new RdrfException(ErrorCode.FileTooLarge, "CtrCryptStream exceeded 64 GiB CTR safety limit.");

                try
                {
                    int offset = 0;
                    while (offset < bytesRead)
                    {
                        int chunk = Math.Min(KeyBlockLen, bytesRead - offset);
                        GenerateKeystreamBatched(keyBlockArr.AsSpan(0, chunk), rk, ref counter);
                        XorSpan(buffer.AsSpan(offset, chunk), keyBlockArr.AsSpan(0, chunk));
                        offset += chunk;
                    }
                    output.Write(buffer, 0, bytesRead);
                }
                finally
                {
                    SCryptography.CryptographicOperations.ZeroMemory(keyBlockArr.AsSpan());
                }
            }
        }
        else
        {
            CtrCryptStreamFallback(input, output, aesKey, nonce, bufferSize);
        }
    }

    private static void CtrCryptStreamFallback(Stream input, Stream output,
        byte[] aesKey, byte[] nonce, int bufferSize)
    {
        using var aes = SCryptography.Aes.Create();
        aes.Key = aesKey;
        aes.Mode = SCryptography.CipherMode.ECB;
        aes.Padding = SCryptography.PaddingMode.None;
        using var encryptor = aes.CreateEncryptor();

        var counter = BuildCounter(nonce);
        byte[] buffer = new byte[bufferSize];

        while (true)
        {
            int bytesRead = input.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0) break;

            int blockCount = (bytesRead + 15) / 16;
            int bufSize = blockCount * 16;
            byte[] counters = ArrayPool<byte>.Shared.Rent(bufSize);
            byte[] keystream = ArrayPool<byte>.Shared.Rent(bufSize);
            try
            {
                Span<byte> ctr = new byte[16];
                MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref counter, 1)).CopyTo(ctr);

                var countSpan = counters.AsSpan(0, bufSize);
                for (int ci = 0; ci < blockCount; ci++)
                {
                    ctr.CopyTo(countSpan.Slice(ci * 16, 16));
                    for (int j = 15; j >= 0; j--)
                        if (++ctr[j] != 0) break;
                }
                counter = MemoryMarshal.Read<Vector128<byte>>(ctr);

                encryptor.TransformBlock(counters, 0, bufSize, keystream, 0);

                XorSpan(buffer.AsSpan(0, bytesRead), keystream.AsSpan(0, bytesRead));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(counters, clearArray: true);
                ArrayPool<byte>.Shared.Return(keystream, clearArray: true);
            }

            output.Write(buffer, 0, bytesRead);
        }
    }

    // -- Key Expansion (AES-256, 15 round keys) --

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

    // -- Counter --

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

    // -- AES-256 Encrypt Single Block (14 rounds) --

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

    // -- Core AES-NI CTR Loop (8-block batched, round-by-round interleaving) --

    private static void CtrCryptCoreAesNi(ReadOnlySpan<byte> src, Span<byte> dst,
        Vector128<byte>[] rk, ref Vector128<byte> counter)
    {
        int i = 0;
        const int B = 8;

        // 8-block batched: process 128 bytes per iteration with round-by-round interleaving
        for (; i + B * 16 <= src.Length; i += B * 16)
        {
            // Phase 1: generate B counters
            var c0 = counter; counter = IncrementCounter(counter);
            var c1 = counter; counter = IncrementCounter(counter);
            var c2 = counter; counter = IncrementCounter(counter);
            var c3 = counter; counter = IncrementCounter(counter);
            var c4 = counter; counter = IncrementCounter(counter);
            var c5 = counter; counter = IncrementCounter(counter);
            var c6 = counter; counter = IncrementCounter(counter);
            var c7 = counter; counter = IncrementCounter(counter);

            // Phase 2: AES encrypt all B blocks, round by round (interleaved)
            var s0 = Vector128.Xor(c0, rk[0]); var s1 = Vector128.Xor(c1, rk[0]);
            var s2 = Vector128.Xor(c2, rk[0]); var s3 = Vector128.Xor(c3, rk[0]);
            var s4 = Vector128.Xor(c4, rk[0]); var s5 = Vector128.Xor(c5, rk[0]);
            var s6 = Vector128.Xor(c6, rk[0]); var s7 = Vector128.Xor(c7, rk[0]);

            // Rounds 1-13 with Aes.Encrypt
            for (int r = 1; r <= 13; r++)
            {
                var rk_r = rk[r];
                s0 = Aes.Encrypt(s0, rk_r); s1 = Aes.Encrypt(s1, rk_r);
                s2 = Aes.Encrypt(s2, rk_r); s3 = Aes.Encrypt(s3, rk_r);
                s4 = Aes.Encrypt(s4, rk_r); s5 = Aes.Encrypt(s5, rk_r);
                s6 = Aes.Encrypt(s6, rk_r); s7 = Aes.Encrypt(s7, rk_r);
            }

            // Round 14 (Aes.EncryptLast)
            s0 = Aes.EncryptLast(s0, rk[14]); s1 = Aes.EncryptLast(s1, rk[14]);
            s2 = Aes.EncryptLast(s2, rk[14]); s3 = Aes.EncryptLast(s3, rk[14]);
            s4 = Aes.EncryptLast(s4, rk[14]); s5 = Aes.EncryptLast(s5, rk[14]);
            s6 = Aes.EncryptLast(s6, rk[14]); s7 = Aes.EncryptLast(s7, rk[14]);

            // Phase 3: XOR with data
            if (Avx2.IsSupported)
            {
                ref var d0 = ref MemoryMarshal.GetReference(src.Slice(i));
                Avx2.Xor(Vector256.Create(s0, s1), Vector256.LoadUnsafe(ref d0)).CopyTo(dst.Slice(i));
                ref var d2 = ref MemoryMarshal.GetReference(src.Slice(i + 32));
                Avx2.Xor(Vector256.Create(s2, s3), Vector256.LoadUnsafe(ref d2)).CopyTo(dst.Slice(i + 32));
                ref var d4 = ref MemoryMarshal.GetReference(src.Slice(i + 64));
                Avx2.Xor(Vector256.Create(s4, s5), Vector256.LoadUnsafe(ref d4)).CopyTo(dst.Slice(i + 64));
                ref var d6 = ref MemoryMarshal.GetReference(src.Slice(i + 96));
                Avx2.Xor(Vector256.Create(s6, s7), Vector256.LoadUnsafe(ref d6)).CopyTo(dst.Slice(i + 96));
            }
            else
            {
                ref var d0 = ref MemoryMarshal.GetReference(src.Slice(i));
                Vector128.Xor(s0, Vector128.LoadUnsafe(ref d0)).CopyTo(dst.Slice(i));
                ref var d1 = ref MemoryMarshal.GetReference(src.Slice(i + 16));
                Vector128.Xor(s1, Vector128.LoadUnsafe(ref d1)).CopyTo(dst.Slice(i + 16));
                ref var d2 = ref MemoryMarshal.GetReference(src.Slice(i + 32));
                Vector128.Xor(s2, Vector128.LoadUnsafe(ref d2)).CopyTo(dst.Slice(i + 32));
                ref var d3 = ref MemoryMarshal.GetReference(src.Slice(i + 48));
                Vector128.Xor(s3, Vector128.LoadUnsafe(ref d3)).CopyTo(dst.Slice(i + 48));
                ref var d4 = ref MemoryMarshal.GetReference(src.Slice(i + 64));
                Vector128.Xor(s4, Vector128.LoadUnsafe(ref d4)).CopyTo(dst.Slice(i + 64));
                ref var d5 = ref MemoryMarshal.GetReference(src.Slice(i + 80));
                Vector128.Xor(s5, Vector128.LoadUnsafe(ref d5)).CopyTo(dst.Slice(i + 80));
                ref var d6 = ref MemoryMarshal.GetReference(src.Slice(i + 96));
                Vector128.Xor(s6, Vector128.LoadUnsafe(ref d6)).CopyTo(dst.Slice(i + 96));
                ref var d7 = ref MemoryMarshal.GetReference(src.Slice(i + 112));
                Vector128.Xor(s7, Vector128.LoadUnsafe(ref d7)).CopyTo(dst.Slice(i + 112));
            }
        }

        // Remaining full blocks (< 8 blocks)
        for (; i + 16 <= src.Length; i += 16)
        {
            var keystream = AesEncryptBlock(counter, rk);
            counter = IncrementCounter(counter);
            ref var s = ref MemoryMarshal.GetReference(src.Slice(i));
            Vector128.Xor(keystream, Vector128.LoadUnsafe(ref s)).CopyTo(dst.Slice(i));
        }

        // Tail (< 16 bytes)
        if (i < src.Length)
        {
            var keystream = AesEncryptBlock(counter, rk);
            int remain = src.Length - i;
            for (int j = 0; j < remain; j++)
                dst[i + j] = (byte)(src[i + j] ^ keystream.GetElement(j));
        }
    }

    // -- Batched keystream generation (8-block interleaved) --

    private static void GenerateKeystreamBatched(Span<byte> dst, Vector128<byte>[] rk, ref Vector128<byte> counter)
    {
        int i = 0;
        const int B = 8;

        for (; i + B * 16 <= dst.Length; i += B * 16)
        {
            var c0 = counter; counter = IncrementCounter(counter);
            var c1 = counter; counter = IncrementCounter(counter);
            var c2 = counter; counter = IncrementCounter(counter);
            var c3 = counter; counter = IncrementCounter(counter);
            var c4 = counter; counter = IncrementCounter(counter);
            var c5 = counter; counter = IncrementCounter(counter);
            var c6 = counter; counter = IncrementCounter(counter);
            var c7 = counter; counter = IncrementCounter(counter);

            var s0 = Vector128.Xor(c0, rk[0]); var s1 = Vector128.Xor(c1, rk[0]);
            var s2 = Vector128.Xor(c2, rk[0]); var s3 = Vector128.Xor(c3, rk[0]);
            var s4 = Vector128.Xor(c4, rk[0]); var s5 = Vector128.Xor(c5, rk[0]);
            var s6 = Vector128.Xor(c6, rk[0]); var s7 = Vector128.Xor(c7, rk[0]);

            for (int r = 1; r <= 13; r++)
            {
                var rk_r = rk[r];
                s0 = Aes.Encrypt(s0, rk_r); s1 = Aes.Encrypt(s1, rk_r);
                s2 = Aes.Encrypt(s2, rk_r); s3 = Aes.Encrypt(s3, rk_r);
                s4 = Aes.Encrypt(s4, rk_r); s5 = Aes.Encrypt(s5, rk_r);
                s6 = Aes.Encrypt(s6, rk_r); s7 = Aes.Encrypt(s7, rk_r);
            }

            s0 = Aes.EncryptLast(s0, rk[14]); s1 = Aes.EncryptLast(s1, rk[14]);
            s2 = Aes.EncryptLast(s2, rk[14]); s3 = Aes.EncryptLast(s3, rk[14]);
            s4 = Aes.EncryptLast(s4, rk[14]); s5 = Aes.EncryptLast(s5, rk[14]);
            s6 = Aes.EncryptLast(s6, rk[14]); s7 = Aes.EncryptLast(s7, rk[14]);

            s0.CopyTo(dst.Slice(i, 16)); s1.CopyTo(dst.Slice(i + 16, 16));
            s2.CopyTo(dst.Slice(i + 32, 16)); s3.CopyTo(dst.Slice(i + 48, 16));
            s4.CopyTo(dst.Slice(i + 64, 16)); s5.CopyTo(dst.Slice(i + 80, 16));
            s6.CopyTo(dst.Slice(i + 96, 16)); s7.CopyTo(dst.Slice(i + 112, 16));
        }

        // Remaining full blocks (1-7)
        for (; i + 16 <= dst.Length; i += 16)
        {
            AesEncryptBlock(counter, rk).CopyTo(dst.Slice(i, 16));
            counter = IncrementCounter(counter);
        }

        // Tail bytes: generate last block, copy partial
        if (i < dst.Length)
        {
            var tailKs = AesEncryptBlock(counter, rk);
            counter = IncrementCounter(counter);
            var ksSpan = MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref tailKs, 1));
            ksSpan.Slice(0, dst.Length - i).CopyTo(dst.Slice(i));
        }
    }

    // -- XorSpan: SIMD XOR with AVX2/SSE2 fallback --

    private static void XorSpan(Span<byte> buffer, ReadOnlySpan<byte> keystream)
    {
        int xorIdx = 0;
        if (Avx2.IsSupported)
        {
            for (; xorIdx + 32 <= buffer.Length; xorIdx += 32)
                Avx2.Xor(
                    Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(buffer.Slice(xorIdx))),
                    Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(keystream.Slice(xorIdx))))
                    .CopyTo(buffer.Slice(xorIdx));
        }
        for (; xorIdx + 16 <= buffer.Length; xorIdx += 16)
            Vector128.Xor(
                Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(buffer.Slice(xorIdx))),
                Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(keystream.Slice(xorIdx))))
                .CopyTo(buffer.Slice(xorIdx));
        for (; xorIdx < buffer.Length; xorIdx++)
            buffer[xorIdx] ^= keystream[xorIdx];
    }

    // -- Fallback (batch TransformBlock) --

    private static void CtrCryptCoreFallback(ReadOnlySpan<byte> src, Span<byte> dst, byte[] aesKey, byte[] nonce)
    {
        if (src.Length == 0) return;
        int blockCount = (src.Length + 15) / 16;
        int bufSize = blockCount * 16;
        byte[] counters = ArrayPool<byte>.Shared.Rent(bufSize);
        byte[] keystream = ArrayPool<byte>.Shared.Rent(bufSize);
        try
        {
            Span<byte> ctr = stackalloc byte[16];
            nonce.AsSpan(0, Math.Min(nonce.Length, 12)).CopyTo(ctr);
            ctr[15] = 1;

            var countSpan = counters.AsSpan(0, bufSize);
            for (int ci = 0; ci < blockCount; ci++)
            {
                ctr.CopyTo(countSpan.Slice(ci * 16, 16));
                for (int j = 15; j >= 0; j--)
                    if (++ctr[j] != 0) break;
            }

            using var aes = SCryptography.Aes.Create();
            aes.Key = aesKey;
            aes.Mode = SCryptography.CipherMode.ECB;
            aes.Padding = SCryptography.PaddingMode.None;
            using var encryptor = aes.CreateEncryptor();
            encryptor.TransformBlock(counters, 0, bufSize, keystream, 0);

            src.CopyTo(dst);
            XorSpan(dst, keystream.AsSpan(0, src.Length));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(counters, clearArray: true);
            ArrayPool<byte>.Shared.Return(keystream, clearArray: true);
        }
    }
}



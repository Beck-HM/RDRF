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

    // ── Core AES-NI CTR Loop (16-block batched, round-by-round interleaving) ──

    private static void CtrCryptCoreAesNi(ReadOnlySpan<byte> src, Span<byte> dst,
        Vector128<byte>[] rk, ref Vector128<byte> counter)
    {
        int i = 0;

        // 16-block batched: process 256 bytes per iteration
        for (; i + 256 <= src.Length; i += 256)
        {
            // Phase 1: generate 16 counters
            var c0 = counter; counter = IncrementCounter(counter);
            var c1 = counter; counter = IncrementCounter(counter);
            var c2 = counter; counter = IncrementCounter(counter);
            var c3 = counter; counter = IncrementCounter(counter);
            var c4 = counter; counter = IncrementCounter(counter);
            var c5 = counter; counter = IncrementCounter(counter);
            var c6 = counter; counter = IncrementCounter(counter);
            var c7 = counter; counter = IncrementCounter(counter);
            var c8 = counter; counter = IncrementCounter(counter);
            var c9 = counter; counter = IncrementCounter(counter);
            var c10 = counter; counter = IncrementCounter(counter);
            var c11 = counter; counter = IncrementCounter(counter);
            var c12 = counter; counter = IncrementCounter(counter);
            var c13 = counter; counter = IncrementCounter(counter);
            var c14 = counter; counter = IncrementCounter(counter);
            var c15 = counter; counter = IncrementCounter(counter);

            // Phase 2: AES encrypt all 16 blocks, round by round
            var s0 = Vector128.Xor(c0, rk[0]); var s1 = Vector128.Xor(c1, rk[0]);
            var s2 = Vector128.Xor(c2, rk[0]); var s3 = Vector128.Xor(c3, rk[0]);
            var s4 = Vector128.Xor(c4, rk[0]); var s5 = Vector128.Xor(c5, rk[0]);
            var s6 = Vector128.Xor(c6, rk[0]); var s7 = Vector128.Xor(c7, rk[0]);
            var s8 = Vector128.Xor(c8, rk[0]); var s9 = Vector128.Xor(c9, rk[0]);
            var s10 = Vector128.Xor(c10, rk[0]); var s11 = Vector128.Xor(c11, rk[0]);
            var s12 = Vector128.Xor(c12, rk[0]); var s13 = Vector128.Xor(c13, rk[0]);
            var s14 = Vector128.Xor(c14, rk[0]); var s15 = Vector128.Xor(c15, rk[0]);

            // Rounds 1-13
            var rk1 = rk[1]; s0 = Aes.Encrypt(s0, rk1); s1 = Aes.Encrypt(s1, rk1); s2 = Aes.Encrypt(s2, rk1); s3 = Aes.Encrypt(s3, rk1); s4 = Aes.Encrypt(s4, rk1); s5 = Aes.Encrypt(s5, rk1); s6 = Aes.Encrypt(s6, rk1); s7 = Aes.Encrypt(s7, rk1); s8 = Aes.Encrypt(s8, rk1); s9 = Aes.Encrypt(s9, rk1); s10 = Aes.Encrypt(s10, rk1); s11 = Aes.Encrypt(s11, rk1); s12 = Aes.Encrypt(s12, rk1); s13 = Aes.Encrypt(s13, rk1); s14 = Aes.Encrypt(s14, rk1); s15 = Aes.Encrypt(s15, rk1);
            var rk2 = rk[2]; s0 = Aes.Encrypt(s0, rk2); s1 = Aes.Encrypt(s1, rk2); s2 = Aes.Encrypt(s2, rk2); s3 = Aes.Encrypt(s3, rk2); s4 = Aes.Encrypt(s4, rk2); s5 = Aes.Encrypt(s5, rk2); s6 = Aes.Encrypt(s6, rk2); s7 = Aes.Encrypt(s7, rk2); s8 = Aes.Encrypt(s8, rk2); s9 = Aes.Encrypt(s9, rk2); s10 = Aes.Encrypt(s10, rk2); s11 = Aes.Encrypt(s11, rk2); s12 = Aes.Encrypt(s12, rk2); s13 = Aes.Encrypt(s13, rk2); s14 = Aes.Encrypt(s14, rk2); s15 = Aes.Encrypt(s15, rk2);
            var rk3 = rk[3]; s0 = Aes.Encrypt(s0, rk3); s1 = Aes.Encrypt(s1, rk3); s2 = Aes.Encrypt(s2, rk3); s3 = Aes.Encrypt(s3, rk3); s4 = Aes.Encrypt(s4, rk3); s5 = Aes.Encrypt(s5, rk3); s6 = Aes.Encrypt(s6, rk3); s7 = Aes.Encrypt(s7, rk3); s8 = Aes.Encrypt(s8, rk3); s9 = Aes.Encrypt(s9, rk3); s10 = Aes.Encrypt(s10, rk3); s11 = Aes.Encrypt(s11, rk3); s12 = Aes.Encrypt(s12, rk3); s13 = Aes.Encrypt(s13, rk3); s14 = Aes.Encrypt(s14, rk3); s15 = Aes.Encrypt(s15, rk3);
            var rk4 = rk[4]; s0 = Aes.Encrypt(s0, rk4); s1 = Aes.Encrypt(s1, rk4); s2 = Aes.Encrypt(s2, rk4); s3 = Aes.Encrypt(s3, rk4); s4 = Aes.Encrypt(s4, rk4); s5 = Aes.Encrypt(s5, rk4); s6 = Aes.Encrypt(s6, rk4); s7 = Aes.Encrypt(s7, rk4); s8 = Aes.Encrypt(s8, rk4); s9 = Aes.Encrypt(s9, rk4); s10 = Aes.Encrypt(s10, rk4); s11 = Aes.Encrypt(s11, rk4); s12 = Aes.Encrypt(s12, rk4); s13 = Aes.Encrypt(s13, rk4); s14 = Aes.Encrypt(s14, rk4); s15 = Aes.Encrypt(s15, rk4);
            var rk5 = rk[5]; s0 = Aes.Encrypt(s0, rk5); s1 = Aes.Encrypt(s1, rk5); s2 = Aes.Encrypt(s2, rk5); s3 = Aes.Encrypt(s3, rk5); s4 = Aes.Encrypt(s4, rk5); s5 = Aes.Encrypt(s5, rk5); s6 = Aes.Encrypt(s6, rk5); s7 = Aes.Encrypt(s7, rk5); s8 = Aes.Encrypt(s8, rk5); s9 = Aes.Encrypt(s9, rk5); s10 = Aes.Encrypt(s10, rk5); s11 = Aes.Encrypt(s11, rk5); s12 = Aes.Encrypt(s12, rk5); s13 = Aes.Encrypt(s13, rk5); s14 = Aes.Encrypt(s14, rk5); s15 = Aes.Encrypt(s15, rk5);
            var rk6 = rk[6]; s0 = Aes.Encrypt(s0, rk6); s1 = Aes.Encrypt(s1, rk6); s2 = Aes.Encrypt(s2, rk6); s3 = Aes.Encrypt(s3, rk6); s4 = Aes.Encrypt(s4, rk6); s5 = Aes.Encrypt(s5, rk6); s6 = Aes.Encrypt(s6, rk6); s7 = Aes.Encrypt(s7, rk6); s8 = Aes.Encrypt(s8, rk6); s9 = Aes.Encrypt(s9, rk6); s10 = Aes.Encrypt(s10, rk6); s11 = Aes.Encrypt(s11, rk6); s12 = Aes.Encrypt(s12, rk6); s13 = Aes.Encrypt(s13, rk6); s14 = Aes.Encrypt(s14, rk6); s15 = Aes.Encrypt(s15, rk6);
            var rk7 = rk[7]; s0 = Aes.Encrypt(s0, rk7); s1 = Aes.Encrypt(s1, rk7); s2 = Aes.Encrypt(s2, rk7); s3 = Aes.Encrypt(s3, rk7); s4 = Aes.Encrypt(s4, rk7); s5 = Aes.Encrypt(s5, rk7); s6 = Aes.Encrypt(s6, rk7); s7 = Aes.Encrypt(s7, rk7); s8 = Aes.Encrypt(s8, rk7); s9 = Aes.Encrypt(s9, rk7); s10 = Aes.Encrypt(s10, rk7); s11 = Aes.Encrypt(s11, rk7); s12 = Aes.Encrypt(s12, rk7); s13 = Aes.Encrypt(s13, rk7); s14 = Aes.Encrypt(s14, rk7); s15 = Aes.Encrypt(s15, rk7);
            var rk8 = rk[8]; s0 = Aes.Encrypt(s0, rk8); s1 = Aes.Encrypt(s1, rk8); s2 = Aes.Encrypt(s2, rk8); s3 = Aes.Encrypt(s3, rk8); s4 = Aes.Encrypt(s4, rk8); s5 = Aes.Encrypt(s5, rk8); s6 = Aes.Encrypt(s6, rk8); s7 = Aes.Encrypt(s7, rk8); s8 = Aes.Encrypt(s8, rk8); s9 = Aes.Encrypt(s9, rk8); s10 = Aes.Encrypt(s10, rk8); s11 = Aes.Encrypt(s11, rk8); s12 = Aes.Encrypt(s12, rk8); s13 = Aes.Encrypt(s13, rk8); s14 = Aes.Encrypt(s14, rk8); s15 = Aes.Encrypt(s15, rk8);
            var rk9 = rk[9]; s0 = Aes.Encrypt(s0, rk9); s1 = Aes.Encrypt(s1, rk9); s2 = Aes.Encrypt(s2, rk9); s3 = Aes.Encrypt(s3, rk9); s4 = Aes.Encrypt(s4, rk9); s5 = Aes.Encrypt(s5, rk9); s6 = Aes.Encrypt(s6, rk9); s7 = Aes.Encrypt(s7, rk9); s8 = Aes.Encrypt(s8, rk9); s9 = Aes.Encrypt(s9, rk9); s10 = Aes.Encrypt(s10, rk9); s11 = Aes.Encrypt(s11, rk9); s12 = Aes.Encrypt(s12, rk9); s13 = Aes.Encrypt(s13, rk9); s14 = Aes.Encrypt(s14, rk9); s15 = Aes.Encrypt(s15, rk9);
            var rk10 = rk[10]; s0 = Aes.Encrypt(s0, rk10); s1 = Aes.Encrypt(s1, rk10); s2 = Aes.Encrypt(s2, rk10); s3 = Aes.Encrypt(s3, rk10); s4 = Aes.Encrypt(s4, rk10); s5 = Aes.Encrypt(s5, rk10); s6 = Aes.Encrypt(s6, rk10); s7 = Aes.Encrypt(s7, rk10); s8 = Aes.Encrypt(s8, rk10); s9 = Aes.Encrypt(s9, rk10); s10 = Aes.Encrypt(s10, rk10); s11 = Aes.Encrypt(s11, rk10); s12 = Aes.Encrypt(s12, rk10); s13 = Aes.Encrypt(s13, rk10); s14 = Aes.Encrypt(s14, rk10); s15 = Aes.Encrypt(s15, rk10);
            var rk11 = rk[11]; s0 = Aes.Encrypt(s0, rk11); s1 = Aes.Encrypt(s1, rk11); s2 = Aes.Encrypt(s2, rk11); s3 = Aes.Encrypt(s3, rk11); s4 = Aes.Encrypt(s4, rk11); s5 = Aes.Encrypt(s5, rk11); s6 = Aes.Encrypt(s6, rk11); s7 = Aes.Encrypt(s7, rk11); s8 = Aes.Encrypt(s8, rk11); s9 = Aes.Encrypt(s9, rk11); s10 = Aes.Encrypt(s10, rk11); s11 = Aes.Encrypt(s11, rk11); s12 = Aes.Encrypt(s12, rk11); s13 = Aes.Encrypt(s13, rk11); s14 = Aes.Encrypt(s14, rk11); s15 = Aes.Encrypt(s15, rk11);
            var rk12 = rk[12]; s0 = Aes.Encrypt(s0, rk12); s1 = Aes.Encrypt(s1, rk12); s2 = Aes.Encrypt(s2, rk12); s3 = Aes.Encrypt(s3, rk12); s4 = Aes.Encrypt(s4, rk12); s5 = Aes.Encrypt(s5, rk12); s6 = Aes.Encrypt(s6, rk12); s7 = Aes.Encrypt(s7, rk12); s8 = Aes.Encrypt(s8, rk12); s9 = Aes.Encrypt(s9, rk12); s10 = Aes.Encrypt(s10, rk12); s11 = Aes.Encrypt(s11, rk12); s12 = Aes.Encrypt(s12, rk12); s13 = Aes.Encrypt(s13, rk12); s14 = Aes.Encrypt(s14, rk12); s15 = Aes.Encrypt(s15, rk12);
            var rk13 = rk[13]; s0 = Aes.Encrypt(s0, rk13); s1 = Aes.Encrypt(s1, rk13); s2 = Aes.Encrypt(s2, rk13); s3 = Aes.Encrypt(s3, rk13); s4 = Aes.Encrypt(s4, rk13); s5 = Aes.Encrypt(s5, rk13); s6 = Aes.Encrypt(s6, rk13); s7 = Aes.Encrypt(s7, rk13); s8 = Aes.Encrypt(s8, rk13); s9 = Aes.Encrypt(s9, rk13); s10 = Aes.Encrypt(s10, rk13); s11 = Aes.Encrypt(s11, rk13); s12 = Aes.Encrypt(s12, rk13); s13 = Aes.Encrypt(s13, rk13); s14 = Aes.Encrypt(s14, rk13); s15 = Aes.Encrypt(s15, rk13);

            // Round 14 (Aes.EncryptLast)
            var rk14 = rk[14];
            s0 = Aes.EncryptLast(s0, rk14); s1 = Aes.EncryptLast(s1, rk14);
            s2 = Aes.EncryptLast(s2, rk14); s3 = Aes.EncryptLast(s3, rk14);
            s4 = Aes.EncryptLast(s4, rk14); s5 = Aes.EncryptLast(s5, rk14);
            s6 = Aes.EncryptLast(s6, rk14); s7 = Aes.EncryptLast(s7, rk14);
            s8 = Aes.EncryptLast(s8, rk14); s9 = Aes.EncryptLast(s9, rk14);
            s10 = Aes.EncryptLast(s10, rk14); s11 = Aes.EncryptLast(s11, rk14);
            s12 = Aes.EncryptLast(s12, rk14); s13 = Aes.EncryptLast(s13, rk14);
            s14 = Aes.EncryptLast(s14, rk14); s15 = Aes.EncryptLast(s15, rk14);

            // Phase 3: XOR with data using AVX2
            if (Avx2.IsSupported)
            {
                var d0 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i)));
                Avx2.Xor(Vector256.Create(s0, s1), d0).CopyTo(dst.Slice(i));
                var d2 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 32)));
                Avx2.Xor(Vector256.Create(s2, s3), d2).CopyTo(dst.Slice(i + 32));
                var d4 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 64)));
                Avx2.Xor(Vector256.Create(s4, s5), d4).CopyTo(dst.Slice(i + 64));
                var d6 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 96)));
                Avx2.Xor(Vector256.Create(s6, s7), d6).CopyTo(dst.Slice(i + 96));
                var d8 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 128)));
                Avx2.Xor(Vector256.Create(s8, s9), d8).CopyTo(dst.Slice(i + 128));
                var d10 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 160)));
                Avx2.Xor(Vector256.Create(s10, s11), d10).CopyTo(dst.Slice(i + 160));
                var d12 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 192)));
                Avx2.Xor(Vector256.Create(s12, s13), d12).CopyTo(dst.Slice(i + 192));
                var d14 = Vector256.LoadUnsafe(ref MemoryMarshal.GetReference(src.Slice(i + 224)));
                Avx2.Xor(Vector256.Create(s14, s15), d14).CopyTo(dst.Slice(i + 224));
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
                ref var d8 = ref MemoryMarshal.GetReference(src.Slice(i + 128));
                Vector128.Xor(s8, Vector128.LoadUnsafe(ref d8)).CopyTo(dst.Slice(i + 128));
                ref var d9 = ref MemoryMarshal.GetReference(src.Slice(i + 144));
                Vector128.Xor(s9, Vector128.LoadUnsafe(ref d9)).CopyTo(dst.Slice(i + 144));
                ref var d10 = ref MemoryMarshal.GetReference(src.Slice(i + 160));
                Vector128.Xor(s10, Vector128.LoadUnsafe(ref d10)).CopyTo(dst.Slice(i + 160));
                ref var d11 = ref MemoryMarshal.GetReference(src.Slice(i + 176));
                Vector128.Xor(s11, Vector128.LoadUnsafe(ref d11)).CopyTo(dst.Slice(i + 176));
                ref var d12 = ref MemoryMarshal.GetReference(src.Slice(i + 192));
                Vector128.Xor(s12, Vector128.LoadUnsafe(ref d12)).CopyTo(dst.Slice(i + 192));
                ref var d13 = ref MemoryMarshal.GetReference(src.Slice(i + 208));
                Vector128.Xor(s13, Vector128.LoadUnsafe(ref d13)).CopyTo(dst.Slice(i + 208));
                ref var d14 = ref MemoryMarshal.GetReference(src.Slice(i + 224));
                Vector128.Xor(s14, Vector128.LoadUnsafe(ref d14)).CopyTo(dst.Slice(i + 224));
                ref var d15 = ref MemoryMarshal.GetReference(src.Slice(i + 240));
                Vector128.Xor(s15, Vector128.LoadUnsafe(ref d15)).CopyTo(dst.Slice(i + 240));
            }
        }

        // 8-block fallback for remaining data (128-255 bytes)
        for (; i + 128 <= src.Length; i += 128)
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

        // Remaining single blocks (< 128 bytes)
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

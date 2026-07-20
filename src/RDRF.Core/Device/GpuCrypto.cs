using ILGPU;
using ILGPU.Runtime;

namespace RDRF.Core.Device;

public static class GpuCrypto
{
    private const int MinGpuBytes = 1_048_576;
    private const int MaxGpuBytes = 512_000_000; // 512MB — safe upper bound for any CUDA allocation

    /// <summary>Returns true if GPU encryption was performed.</summary>
    public static bool EncryptCtrBatch(byte[] flatPayload, byte[] aesKey, byte[] nonce)
    {
        if (flatPayload.Length < MinGpuBytes || flatPayload.Length > MaxGpuBytes)
            return false;

        try
        {
            var acc = GpuContext.Accelerator;
            int totalBytes = flatPayload.Length;
            int totalBlocks = (totalBytes + 15) / 16;

            var rk = ExpandKey256(aesKey);

            using var dataBuf = acc.Allocate1D<byte>(totalBytes);
            using var rkBuf = acc.Allocate1D<byte>(240);
            using var nonceBuf = acc.Allocate1D<byte>(16);

        dataBuf.CopyFromCPU(flatPayload);
        rkBuf.CopyFromCPU(rk);
        nonceBuf.CopyFromCPU(nonce);

        var kernel = acc.LoadAutoGroupedStreamKernel<
            Index1D, ArrayView<byte>, ArrayView<byte>, ArrayView<byte>>(AesCtrKernel);
        kernel(totalBlocks, dataBuf.View, rkBuf.View, nonceBuf.View);
        acc.Synchronize();

        dataBuf.CopyToCPU(flatPayload);
        return true;
    }
    catch
    {
        return false; // GPU failure → caller falls back to CPU
    }
}

    internal static void AesCtrKernel(Index1D idx, ArrayView<byte> data, ArrayView<byte> rk, ArrayView<byte> nonceView)
    {
        int blockIdx = idx.X;
        int byteOff = blockIdx * 16;
        if ((long)byteOff + 16 > data.Length) return;

        // Initialize state as counter (nonce + blockIdx, big-endian increment)
        byte s0 = nonceView[0], s1 = nonceView[1], s2 = nonceView[2], s3 = nonceView[3];
        byte s4 = nonceView[4], s5 = nonceView[5], s6 = nonceView[6], s7 = nonceView[7];
        byte s8 = nonceView[8], s9 = nonceView[9], sa = nonceView[10], sb = nonceView[11];
        byte sc = nonceView[12], sd = nonceView[13], se = nonceView[14], sf = nonceView[15];

        // Increment counter by blockIdx (little-endian add to bytes 0-7)
        uint lo = (uint)s0 | ((uint)s1 << 8) | ((uint)s2 << 16) | ((uint)s3 << 24);
        uint hi = (uint)s4 | ((uint)s5 << 8) | ((uint)s6 << 16) | ((uint)s7 << 24);
        lo += (uint)blockIdx;
        if (lo < (uint)blockIdx) hi++;
        s0 = (byte)lo; s1 = (byte)(lo >> 8); s2 = (byte)(lo >> 16); s3 = (byte)(lo >> 24);
        s4 = (byte)hi; s5 = (byte)(hi >> 8); s6 = (byte)(hi >> 16); s7 = (byte)(hi >> 24);

        // Add round key 0
        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
        s4 ^= rk[4]; s5 ^= rk[5]; s6 ^= rk[6]; s7 ^= rk[7];
        s8 ^= rk[8]; s9 ^= rk[9]; sa ^= rk[10]; sb ^= rk[11];
        sc ^= rk[12]; sd ^= rk[13]; se ^= rk[14]; sf ^= rk[15];

        // 13 AES rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
        for (int r = 1; r < 14; r++)
        {
            int rkOff = r * 16;
            sub(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref s8, ref s9, ref sa, ref sb, ref sc, ref sd, ref se, ref sf);
            shift(ref s1, ref s5, ref s9, ref sd, ref s2, ref sa, ref s6, ref se, ref s3, ref sf, ref sb, ref s7);
            mix(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref s8, ref s9, ref sa, ref sb, ref sc, ref sd, ref se, ref sf);
            s0 ^= rk[rkOff]; s1 ^= rk[rkOff + 1]; s2 ^= rk[rkOff + 2]; s3 ^= rk[rkOff + 3];
            s4 ^= rk[rkOff + 4]; s5 ^= rk[rkOff + 5]; s6 ^= rk[rkOff + 6]; s7 ^= rk[rkOff + 7];
            s8 ^= rk[rkOff + 8]; s9 ^= rk[rkOff + 9]; sa ^= rk[rkOff + 10]; sb ^= rk[rkOff + 11];
            sc ^= rk[rkOff + 12]; sd ^= rk[rkOff + 13]; se ^= rk[rkOff + 14]; sf ^= rk[rkOff + 15];
        }

        // Last round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
        sub(ref s0, ref s1, ref s2, ref s3, ref s4, ref s5, ref s6, ref s7, ref s8, ref s9, ref sa, ref sb, ref sc, ref sd, ref se, ref sf);
        shift(ref s1, ref s5, ref s9, ref sd, ref s2, ref sa, ref s6, ref se, ref s3, ref sf, ref sb, ref s7);
        s0 ^= rk[224]; s1 ^= rk[225]; s2 ^= rk[226]; s3 ^= rk[227];
        s4 ^= rk[228]; s5 ^= rk[229]; s6 ^= rk[230]; s7 ^= rk[231];
        s8 ^= rk[232]; s9 ^= rk[233]; sa ^= rk[234]; sb ^= rk[235];
        sc ^= rk[236]; sd ^= rk[237]; se ^= rk[238]; sf ^= rk[239];

        // XOR keystream with data (first 16 bytes of this block)
        int end = byteOff + 16;
        if ((long)end > data.Length) end = (int)data.Length;
        switch (end - byteOff)
        {
            case 16: data[byteOff + 15] ^= sf; goto case 15;
            case 15: data[byteOff + 14] ^= se; goto case 14;
            case 14: data[byteOff + 13] ^= sd; goto case 13;
            case 13: data[byteOff + 12] ^= sc; goto case 12;
            case 12: data[byteOff + 11] ^= sb; goto case 11;
            case 11: data[byteOff + 10] ^= sa; goto case 10;
            case 10: data[byteOff + 9] ^= s9; goto case 9;
            case 9: data[byteOff + 8] ^= s8; goto case 8;
            case 8: data[byteOff + 7] ^= s7; goto case 7;
            case 7: data[byteOff + 6] ^= s6; goto case 6;
            case 6: data[byteOff + 5] ^= s5; goto case 5;
            case 5: data[byteOff + 4] ^= s4; goto case 4;
            case 4: data[byteOff + 3] ^= s3; goto case 3;
            case 3: data[byteOff + 2] ^= s2; goto case 2;
            case 2: data[byteOff + 1] ^= s1; goto case 1;
            case 1: data[byteOff] ^= s0; break;
        }
    }

    // --- AES SubBytes (S-box lookup) ---
    private static void sub(ref byte s0, ref byte s1, ref byte s2, ref byte s3, ref byte s4, ref byte s5, ref byte s6, ref byte s7, ref byte s8, ref byte s9, ref byte sa, ref byte sb, ref byte sc, ref byte sd, ref byte se, ref byte sf)
    {
        s0 = SBOX[s0]; s1 = SBOX[s1]; s2 = SBOX[s2]; s3 = SBOX[s3];
        s4 = SBOX[s4]; s5 = SBOX[s5]; s6 = SBOX[s6]; s7 = SBOX[s7];
        s8 = SBOX[s8]; s9 = SBOX[s9]; sa = SBOX[sa]; sb = SBOX[sb];
        sc = SBOX[sc]; sd = SBOX[sd]; se = SBOX[se]; sf = SBOX[sf];
    }

    // --- ShiftRows ---
    private static void shift(ref byte s1, ref byte s5, ref byte s9, ref byte sd, ref byte s2, ref byte sa, ref byte s6, ref byte se, ref byte s3, ref byte sf, ref byte sb, ref byte s7)
    {
        byte t = s1; s1 = s5; s5 = s9; s9 = sd; sd = t;
        t = s2; s2 = sa; sa = t; t = s6; s6 = se; se = t;
        t = s3; s3 = sf; sf = s7; s7 = sb; sb = t;
    }

    // --- MixColumns (one column) ---
    private static void mixCol(ref byte a0, ref byte a1, ref byte a2, ref byte a3)
    {
        byte t = (byte)(a0 ^ a1 ^ a2 ^ a3);
        byte u = a0;
        byte v = (byte)(MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3);
        a0 = v;
        a1 = (byte)(u ^ MUL2[a1] ^ MUL3[a2] ^ a3);
        a2 = (byte)(u ^ a1 ^ MUL2[a2] ^ MUL3[a3]);
        a3 = (byte)(MUL3[u] ^ a1 ^ a2 ^ MUL2[a3]);
    }

    private static void mix(ref byte s0, ref byte s1, ref byte s2, ref byte s3, ref byte s4, ref byte s5, ref byte s6, ref byte s7, ref byte s8, ref byte s9, ref byte sa, ref byte sb, ref byte sc, ref byte sd, ref byte se, ref byte sf)
    {
        mixCol(ref s0, ref s1, ref s2, ref s3); mixCol(ref s4, ref s5, ref s6, ref s7);
        mixCol(ref s8, ref s9, ref sa, ref sb); mixCol(ref sc, ref sd, ref se, ref sf);
    }

    // --- S-box table ---
    private static readonly byte[] SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    ];

    // --- GF(2⁸) multiplication tables ---
    private static readonly byte[] MUL2 = InitMul2();
    private static readonly byte[] MUL3 = InitMul3();

    private static byte[] InitMul2() { var t = new byte[256]; for (int i = 0; i < 256; i++) t[i] = (byte)((i << 1) ^ ((i & 0x80) != 0 ? 0x1B : 0)); return t; }
    private static byte[] InitMul3() { var t = new byte[256]; for (int i = 0; i < 256; i++) t[i] = (byte)(MUL2[i] ^ i); return t; }

    // --- Key expansion (AES-256) ---
    private static readonly byte[] RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    public static byte[] ExpandKey256(byte[] key)
    {
        var rk = new byte[240];
        for (int i = 0; i < 32; i++) rk[i] = key[i];
        for (int i = 8, ki = 32; i < 60; i++, ki += 4)
        {
            byte t0 = rk[ki - 4], t1 = rk[ki - 3], t2 = rk[ki - 2], t3 = rk[ki - 1];
            if (i % 8 == 0) { t0 = (byte)(SBOX[t1] ^ RCON[i / 8 - 1]); t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[t0]; }
            else if (i % 8 == 4) { t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3]; }
            rk[ki] = (byte)(rk[ki - 32] ^ t0); rk[ki + 1] = (byte)(rk[ki - 31] ^ t1);
            rk[ki + 2] = (byte)(rk[ki - 30] ^ t2); rk[ki + 3] = (byte)(rk[ki - 29] ^ t3);
        }
        return rk;
    }
}

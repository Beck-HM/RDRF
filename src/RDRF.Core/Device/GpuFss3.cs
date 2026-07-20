using ILGPU;
using ILGPU.Runtime;

namespace RDRF.Core.Device;

public static class GpuFss3
{
    internal static readonly byte[] GfExp, GfLog;

    static GpuFss3()
    {
        GfExp = new byte[512]; GfLog = new byte[256];
        byte v = 1;
        for (int i = 0; i < 255; i++) { GfExp[i] = v; GfLog[v] = (byte)i; v = (byte)((v << 1) ^ ((v & 0x80) != 0 ? 0x1D : 0)); }
        for (int i = 255; i < 512; i++) GfExp[i] = GfExp[i - 255];
    }

    /// <summary>
    /// GPU-accelerated row parity encode for FSS3. Computes GF(2^8) Vandermonde-weighted
    /// XOR across all K fragments for each of the B rows. P=1 parity only.
    /// </summary>
    public static byte[] RowEncode(byte[] matrix, int K, int B, int subBlockSize)
    {
        var acc = GpuContext.Accelerator;
        int matBytes = K * B * subBlockSize;
        int parityStride = subBlockSize; // 1 parity shard per row

        using var matBuf = acc.Allocate1D<byte>(matBytes);
        using var expBuf = acc.Allocate1D<byte>(512);
        using var logBuf = acc.Allocate1D<byte>(256);
        using var outBuf = acc.Allocate1D<byte>(B * parityStride);

        matBuf.CopyFromCPU(matrix);
        expBuf.CopyFromCPU(GfExp);
        logBuf.CopyFromCPU(GfLog);

        var k = acc.LoadAutoGroupedStreamKernel<
            Index1D, ArrayView<byte>, ArrayView<byte>, ArrayView<byte>, ArrayView<byte>, int, int, int>
            (RowParityKernel);
        k(B, matBuf.View, outBuf.View, expBuf.View, logBuf.View, K, B, subBlockSize);
        acc.Synchronize();

        var result = new byte[B * parityStride];
        outBuf.CopyToCPU(result);
        return result;
    }

    internal static void RowParityKernel(Index1D idx, ArrayView<byte> matrix, ArrayView<byte> output, ArrayView<byte> exp, ArrayView<byte> log, int K, int B, int sb)
    {
        int r = idx.X;
        int outOff = r * sb;

        for (int j = 0; j < sb; j++)
        {
            byte sum = 0;
            for (int f = 0; f < K; f++)
            {
                byte data = matrix[(f * B + r) * sb + j];
                byte coeff = exp[f % 255]; // Vandermonde matrix: ExpTable[k] for first parity
                sum ^= GfMul(coeff, data, exp, log);
            }
            output[outOff + j] = sum;
        }
    }

    private static byte GfMul(byte a, byte b, ArrayView<byte> exp, ArrayView<byte> log)
    {
        if (a == 0 || b == 0) return 0;
        int la = (int)log[(int)a]; int lb = (int)log[(int)b];
        return exp[(la + lb) & 255];
    }
}

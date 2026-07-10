using System.Buffers;
using System.Diagnostics;
using RDRF.Core.Abstractions;
using RDRF.Core.Dssa;
using RDRF.Core.ETN;
using RDRF.Core.Index;

namespace RDRF.Core.FSS;

/// <summary>
/// FSS6.1/6.2 three-node independent repair generation and trailer append runner.
/// </summary>

public static class FssRepairService
{
    // -- FSS6.1 Generation (backup) --

    public static (Fss61RepairData? A, Fss61RepairData? B, Fss61RepairData? C)
        Generate61(byte[] indexBytes, List<byte[]> fragments, byte[] rcBytes, int bs)
    {
        var tA = Task.Run(() => GenLt(indexBytes, bs));
        var tB = Task.Run(() => GenLt(fragments, bs));
        var tC = Task.Run(() => GenLt(rcBytes, bs));
        Task.WaitAll(tA, tB, tC);
        return (tA.Result, tB.Result, tC.Result);
    }

    public static void Append61Trailers(List<byte[]> fragments, string fp,
        Fss61RepairData? a, Fss61RepairData? c)
    {
        if (a == null || c == null) return;
        for (int i = 0; i < fragments.Count; i++)
            fragments[i] = Fss61RepairTrailer.Build(fragments[i], fp, fp, a, c);
    }

    // -- FSS6.2 Generation (backup) --

    public static (Fss62RepairData? A, Fss62RepairData? B, Fss62RepairData? C)
        Generate62(byte[] indexBytes, List<byte[]> fragments, byte[] rcBytes, int bs)
    {
        var tA = Task.Run(() => GenDuip(indexBytes, bs));
        var tB = Task.Run(() => GenDuip(fragments, bs));
        var tC = Task.Run(() => GenDuip(rcBytes, bs));
        Task.WaitAll(tA, tB, tC);
        return (tA.Result, tB.Result, tC.Result);
    }

    public static void Append62Trailers(List<byte[]> fragments, string fp,
        Fss62RepairData? a, Fss62RepairData? c)
    {
        if (a == null || c == null) return;
        for (int i = 0; i < fragments.Count; i++)
            fragments[i] = Fss62RepairTrailer.Build(fragments[i], fp, fp, a, c);
    }

    // -- FSS6.1 Repair (restore) --

    public static bool TryRepair61(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> fragments, CrossValidationResult cv,
        IIndexManager? indexManager = null)
        => RepairRunner.TryFss61(index, ref rcBytes, fragments, cv, indexManager);

    // -- FSS6.2 Repair (restore) --

    public static bool TryRepair62(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> fragments, CrossValidationResult cv,
        IIndexManager? indexManager = null)
        => RepairRunner.TryFss62(index, ref rcBytes, fragments, cv, indexManager);

    // -- Primitives --

    internal static byte[][] SplitToBlocks(byte[] data, int blockSize)
    {
        int count = (data.Length + blockSize - 1) / blockSize;
        var blocks = new byte[count][];
        for (int i = 0; i < count; i++)
            blocks[i] = new byte[blockSize];
        for (int i = 0; i < count; i++)
        {
            int off = i * blockSize;
            int len = Math.Min(blockSize, data.Length - off);
            Buffer.BlockCopy(data, off, blocks[i], 0, len);
        }
        return blocks;
    }

    internal static byte[] MergeBlocks(byte[][] blocks, int originalLength, int blockSize)
    {
        var data = new byte[originalLength];
        for (int i = 0; i < blocks.Length; i++)
        {
            int off = i * blockSize;
            int len = Math.Min(blockSize, originalLength - off);
            Buffer.BlockCopy(blocks[i], 0, data, off, len);
        }
        return data;
    }

    private static Fss61RepairData? GenLt(byte[] src, int bs)
    {
        var blocks = FssRepairService.SplitToBlocks(src, bs);
        if (blocks.Length <= 0) return null;
        int symCount = Math.Max(1, (int)(blocks.Length * LtCode.RepairRatio));
        var (sym, seed) = LtCode.Encode(blocks, symCount, bs);
        var data = new byte[sym.Count * bs];
        for (int i = 0; i < sym.Count; i++)
            Buffer.BlockCopy(sym[i], 0, data, i * bs, bs);
        return new Fss61RepairData
        {
            Seed = seed, BlockCount = blocks.Length, BlockSize = bs, Data = data,
        };
    }

    private static Fss61RepairData? GenLt(List<byte[]> fragments, int bs)
    {
        int totalBlocks = 0;
        foreach (var frag in fragments)
            totalBlocks += (frag.Length + bs - 1) / bs;
        if (totalBlocks <= 0) return null;

        var all = new byte[totalBlocks][];
        int idx = 0;
        foreach (var frag in fragments)
            for (int off = 0; off < frag.Length; off += bs, idx++)
            {
                all[idx] = new byte[bs];
                Buffer.BlockCopy(frag, off, all[idx], 0, Math.Min(bs, frag.Length - off));
            }

        int symCount = Math.Max(1, (int)(totalBlocks * LtCode.RepairRatio));
        var (sym, seed) = LtCode.Encode(all, symCount, bs);
        var data = new byte[sym.Count * bs];
        for (int i = 0; i < sym.Count; i++)
            Buffer.BlockCopy(sym[i], 0, data, i * bs, bs);
        return new Fss61RepairData
        {
            Seed = seed, BlockCount = totalBlocks, BlockSize = bs, Data = data,
        };
    }

    private static Fss62RepairData? GenDuip(byte[] src, int bs)
    {
        var blocks = FssRepairService.SplitToBlocks(src, bs);
        if (blocks.Length <= 0) return null;
        var (sym, entropy, seed) = DuipCode.Encode(blocks, bs);
        var data = new byte[sym.Count * bs];
        for (int i = 0; i < sym.Count; i++)
            Buffer.BlockCopy(sym[i], 0, data, i * bs, bs);
        return new Fss62RepairData
        {
            Seed = seed, BlockCount = blocks.Length, BlockSize = bs,
            Data = data, EntropySamples = entropy,
        };
    }

    private static Fss62RepairData? GenDuip(List<byte[]> fragments, int bs)
    {
        int totalBlocks = 0;
        foreach (var frag in fragments)
            totalBlocks += (frag.Length + bs - 1) / bs;
        if (totalBlocks <= 0) return null;

        var all = new byte[totalBlocks][];
        int idx = 0;
        foreach (var frag in fragments)
            for (int off = 0; off < frag.Length; off += bs, idx++)
            {
                all[idx] = new byte[bs];
                Buffer.BlockCopy(frag, off, all[idx], 0, Math.Min(bs, frag.Length - off));
            }

        var (sym, entropy, seed) = DuipCode.Encode(all, bs);
        var data = new byte[sym.Count * bs];
        for (int i = 0; i < sym.Count; i++)
            Buffer.BlockCopy(sym[i], 0, data, i * bs, bs);
        return new Fss62RepairData
        {
            Seed = seed, BlockCount = totalBlocks, BlockSize = bs,
            Data = data, EntropySamples = entropy,
        };
    }
}

internal static class RepairRunner
{
    internal static bool TryFss61(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> fragments, CrossValidationResult cvResult,
        IIndexManager? idxMgr = null)
    {
        try
        {
            var rcFile = RcFile.FromCbor(rcBytes);
            bool any = false;

            Fss61RepairData? fragA = null, fragC = null;
            foreach (var kvp in fragments)
            {
                var (_, _, _, ra, rc) = Fss61RepairTrailer.Parse(kvp.Value);
                if (ra != null) fragA = ra;
                if (rc != null) fragC = rc;
                if (fragA != null && fragC != null) break;
            }

            if (cvResult.IndexCorrupted)
            {
                var ra = rcFile.RepairA ?? fragA;
                byte[] indexBytes = idxMgr?.SerializeIndex(index) ?? IndexManager.SerializeIndex(index);
                if (ra != null && LtDecode(ra, indexBytes,
                        cvResult.IndexCorruptedBlocks, out var fixedBytes))
                {
                    var fi = idxMgr?.DeserializeIndex(fixedBytes) ?? IndexManager.DeserializeIndex(fixedBytes);
                    if (fi != null)
                    {
                        index.FileFingerprint = fi.FileFingerprint;
                        index.OriginalName = fi.OriginalName;
                        index.OriginalHash = fi.OriginalHash;
                        any = true;
                    }
                }
            }

            if (cvResult.CorruptedFragments.Count > 0)
            {
                var rb = index.Fss61RepairB ?? rcFile.RepairB;
                if (rb != null && RebuildFragments61(fragments, rb, cvResult))
                    any = true;
            }

            if (cvResult.RcCorrupted)
            {
                var rc = index.Fss61RepairC ?? fragC;
                if (rc != null && LtDecode(rc, rcBytes, cvResult.RcCorruptedBlocks, out var fb))
                { rcBytes = fb; any = true; }
            }

            return any;
        }
        catch (Exception ex_fs) { Debug.WriteLine($"TryFss61 failed: {ex_fs.Message}"); return false; }
    }

    internal static bool TryFss62(RdrfIndex index, ref byte[] rcBytes,
        Dictionary<int, byte[]> fragments, CrossValidationResult cvResult,
        IIndexManager? idxMgr = null)
    {
        try
        {
            var rcFile = RcFile.FromCbor(rcBytes);
            bool any = false;

            Fss62RepairData? fragA = null, fragC = null;
            foreach (var kvp in fragments)
            {
                var (_, _, _, ra, rc) = Fss62RepairTrailer.Parse(kvp.Value);
                if (ra != null) fragA = ra;
                if (rc != null) fragC = rc;
                if (fragA != null && fragC != null) break;
            }

            if (cvResult.IndexCorrupted)
            {
                var ra = rcFile.Repair62A ?? fragA;
                if (ra != null)
                {
                    int bs = ra.BlockSize;
                    byte[] idxBytes = idxMgr?.SerializeIndex(index) ?? IndexManager.SerializeIndex(index);
                    var blocks = FssRepairService.SplitToBlocks(idxBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.IndexCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.IndexCorruptedBlocks[i]] = true;
                    int recovered = DuipCode.Decode(blocks, isBad, ra.Data, ra.EntropySamples,
                        blocks.Length, bs, DuipCode.DefaultFaceSize, DuipCode.DefaultEntropyBits);
                    if (recovered >= cvResult.IndexCorruptedBlocks.Count)
                    {
                        var fixedBytes = FssRepairService.MergeBlocks(blocks,
                            idxBytes.Length, bs);
                        var fi = idxMgr?.DeserializeIndex(fixedBytes) ?? IndexManager.DeserializeIndex(fixedBytes);
                        if (fi != null)
                        {
                            index.FileFingerprint = fi.FileFingerprint;
                            index.OriginalName = fi.OriginalName;
                            index.OriginalHash = fi.OriginalHash;
                            any = true;
                        }
                    }
                }
            }

            if (cvResult.CorruptedFragments.Count > 0)
            {
                var rb = index.Fss62RepairB ?? rcFile.Repair62B;
                if (rb != null && RebuildFragments62(fragments, rb, cvResult))
                    any = true;
            }

            if (cvResult.RcCorrupted)
            {
                var rc = index.Fss62RepairC ?? fragC;
                if (rc != null)
                {
                    int bs = rc.BlockSize;
                    var blocks = FssRepairService.SplitToBlocks(rcBytes, bs);
                    var isBad = new bool[blocks.Length];
                    for (int i = 0; i < cvResult.RcCorruptedBlocks.Count && i < blocks.Length; i++)
                        isBad[cvResult.RcCorruptedBlocks[i]] = true;
                    int recovered = DuipCode.Decode(blocks, isBad, rc.Data, rc.EntropySamples,
                        blocks.Length, bs, DuipCode.DefaultFaceSize, DuipCode.DefaultEntropyBits);
                    if (recovered > 0)
                    {
                        rcBytes = FssRepairService.MergeBlocks(blocks, rcBytes.Length, bs);
                        any = true;
                    }
                }
            }
            return any;
        }
        catch (Exception ex_fs2) { Debug.WriteLine($"TryFss62 failed: {ex_fs2.Message}"); return false; }
    }

    private static bool LtDecode(Fss61RepairData rd, byte[] target,
        List<int> badIndices, out byte[] fixedBytes)
    {
        fixedBytes = [];
        int bs = rd.BlockSize;
        var blocks = FssRepairService.SplitToBlocks(target, bs);
        var isBad = new bool[blocks.Length];
        for (int i = 0; i < badIndices.Count && i < blocks.Length; i++)
            isBad[badIndices[i]] = true;
        bool ok = LtCode.Decode(blocks, isBad, rd.Data.Length / bs,
            rd.Seed, rd.Data, blocks.Length, bs);
        if (!ok) return false;
        fixedBytes = FssRepairService.MergeBlocks(blocks, target.Length, bs);
        return true;
    }

    private static bool RebuildFragments61(Dictionary<int, byte[]> fragments,
        Fss61RepairData rb, CrossValidationResult cvResult)
    {
        return RebuildCore(fragments, rb.BlockSize, rb.BlockCount, cvResult,
            (kv) => Fss61RepairTrailer.Parse(kv).Item1,
            (blocks, isBad, total) => LtCode.Decode(blocks, isBad,
                rb.Data.Length / rb.BlockSize, rb.Seed, rb.Data, total, rb.BlockSize));
    }

    private static bool RebuildFragments62(Dictionary<int, byte[]> fragments,
        Fss62RepairData rb, CrossValidationResult cvResult)
    {
        return RebuildCore(fragments, rb.BlockSize, rb.BlockCount, cvResult,
            (kv) => Fss62RepairTrailer.Parse(kv).Item1,
            (blocks, isBad, total) => DuipCode.EnableMultiPass
                ? DuipCode.DecodeMultiPass(blocks, isBad,
                    rb.Data, rb.EntropySamples, total, rb.BlockSize,
                    DuipCode.DefaultFaceSize, DuipCode.DefaultEntropyBits) > 0
                : DuipCode.Decode(blocks, isBad,
                    rb.Data, rb.EntropySamples, total, rb.BlockSize,
                    DuipCode.DefaultFaceSize, DuipCode.DefaultEntropyBits) > 0);
    }

    private static bool RebuildCore(Dictionary<int, byte[]> fragments,
        int blockSize, int blockCount, CrossValidationResult cvResult,
        Func<byte[], byte[]> parseRaw,
        Func<byte[][], bool[], int, bool> decode)
    {
        var sorted = fragments.OrderBy(k => k.Key).ToList();
        int totalBlocks = 0;
        var rawLengths = new List<int>();
        foreach (var kvp in sorted)
        {
            var rawData = parseRaw(kvp.Value);
            rawLengths.Add(rawData.Length);
            totalBlocks += (rawData.Length + blockSize - 1) / blockSize;
        }
        if (totalBlocks != blockCount) return false;

        var allBlocks = new byte[totalBlocks][];
        for (int i = 0; i < totalBlocks; i++)
            allBlocks[i] = new byte[blockSize];
        var isBad = new bool[totalBlocks];

        int gIdx = 0;
        for (int fi = 0; fi < sorted.Count; fi++)
        {
            var rawData = parseRaw(sorted[fi].Value);
            cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
            for (int off = 0; off < rawData.Length; off += blockSize)
            {
                int len = Math.Min(blockSize, rawData.Length - off);
                Buffer.BlockCopy(rawData, off, allBlocks[gIdx], 0, len);
                if (badBlocks != null && badBlocks.Contains(off / blockSize))
                    isBad[gIdx] = true;
                gIdx++;
            }
        }

        if (!decode(allBlocks, isBad, totalBlocks)) return false;

        gIdx = 0;
        for (int fi = 0; fi < sorted.Count; fi++)
        {
            byte[] frag = sorted[fi].Value;
            int rawLen = rawLengths[fi];
            cvResult.CorruptedFragmentBlocks.TryGetValue(fi, out var badBlocks);
            for (int off = 0; off < rawLen; off += blockSize)
            {
                int localIdx = off / blockSize;
                if (badBlocks != null && badBlocks.Contains(localIdx))
                {
                    int len = Math.Min(blockSize, rawLen - off);
                    Buffer.BlockCopy(allBlocks[gIdx], 0, frag, off, len);
                }
                gIdx++;
            }
        }
        return true;
    }
}


using System.Diagnostics;
using RDRF.Core.Abstractions;
using RDRF.Core.Logging;using RDRF.Core.FSS;
using RDRF.Core.Index;
using RDRF.Core.Integrity;

namespace RDRF.Core;

/// <summary>
/// Fragment recovery via missing detection, hash verification, and FSS decode.
/// </summary>

public enum RecoveryStatus
{
    Unknown,
    Complete,
    Partial,
    Failed
}

/// <summary>
/// Fragment recovery via missing detection, hash verification, and FSS decode.
/// </summary>

public class RecoveryResult
{
    public RecoveryStatus Status { get; set; } = RecoveryStatus.Unknown;
    public int TotalFragments { get; set; }
    public int AvailableFragments { get; set; }
    public int MissingFragments { get; set; }
    public int CorruptedFragments { get; set; }
    public int RecoveredFromFss { get; set; }
    public Dictionary<int, byte[]> RecoveredFragments { get; set; } = new();
}

/// <summary>
/// Fragment recovery via missing detection, hash verification, and FSS decode.
/// </summary>

public class RecoveryExecutor : IRecoveryExecutor
{
    private readonly IFSSEngine _fssEngine;

    public RecoveryExecutor(IFSSEngine fssEngine)
    {
        _fssEngine = fssEngine ?? throw new ArgumentNullException(nameof(fssEngine));
    }

    public RecoveryResult ExecuteRecovery(
        RdrfIndex index,
        Dictionary<int, byte[]> availableFragments,
        IMetadataManager? metadata = null)
    {
        var result = new RecoveryResult();
        result.TotalFragments = index.FragmentCount;
        result.AvailableFragments = availableFragments.Count;

        // Step 1: Identify missing fragments
        var missingIndices = new List<int>();
        for (int i = 0; i < index.FragmentCount; i++)
        {
            if (!availableFragments.ContainsKey(i))
            {
                missingIndices.Add(i);
                metadata?.MarkFragmentMissing(index.FileFingerprint, i);
            }
        }
        result.MissingFragments = missingIndices.Count;

        // Step 2: Verify available fragments integrity via index hashes
        var verified = new Dictionary<int, byte[]>();
        var corrupted = new List<int>();

        foreach (var kvp in availableFragments)
        {
            var fragInfo = IndexManager.GetFragmentInfo(index, kvp.Key);
            if (fragInfo != null && !string.IsNullOrEmpty(fragInfo.Hash))
            {
                if (IntegrityChecker.VerifyFragment(kvp.Value, fragInfo.Hash))
                {
                    verified[kvp.Key] = kvp.Value;
                    metadata?.MarkFragmentOk(index.FileFingerprint, kvp.Key);
                }
                else
                {
                    corrupted.Add(kvp.Key);
                    missingIndices.Add(kvp.Key);
                    metadata?.MarkFragmentCorrupt(index.FileFingerprint, kvp.Key);
                }
            }
            else
            {
                verified[kvp.Key] = kvp.Value;
            }
        }
        result.CorruptedFragments = corrupted.Count;

        if (missingIndices.Count == 0)
        {
            result.Status = RecoveryStatus.Complete;
            result.RecoveredFragments = verified;
            return result;
        }

        // Step 3: Try FSS recovery
        if (missingIndices.Count > 0)
        {
            RdrfLogger.Default.Info("",$"[RecoveryExecutor] Attempting FSS recovery: {missingIndices.Count} missing, strategy={index.FssStrategy}");

            try
            {
                var recovered = _fssEngine.Decode(
                    verified,
                    missingIndices,
                    index.FssStrategy,
                    index.FragmentCount,
                    index.OriginalFragmentSizes);

                foreach (var kvp in recovered)
                {
                    if (!verified.ContainsKey(kvp.Key))
                    {
                        verified[kvp.Key] = kvp.Value;
                        result.RecoveredFromFss++;
                    }
                }
            }
            catch (Exception ex)
            {
                RdrfLogger.Default.Info("",$"[RecoveryExecutor] FSS recovery failed: {ex.Message}");
            }
        }

        // Step 4: Final check
        var stillMissing = new List<int>();
        for (int i = 0; i < index.FragmentCount; i++)
            if (!verified.ContainsKey(i))
                stillMissing.Add(i);

        if (stillMissing.Count == 0)
        {
            result.Status = RecoveryStatus.Complete;
        }
        else
        {
            result.Status = RecoveryStatus.Partial;
            RdrfLogger.Default.Info("",$"[RecoveryExecutor] Partial recovery: {stillMissing.Count} fragments still missing");
        }

        result.RecoveredFragments = verified;
        return result;
    }

    public Task<RecoveryResult> ExecuteRecoveryAsync(
        RdrfIndex index,
        Dictionary<int, byte[]> availableFragments,
        IMetadataManager? metadata = null)
    {
        return Task.Run(() => ExecuteRecovery(index, availableFragments, metadata));
    }
}


using System.Text.Json.Serialization;

namespace RDRF.Core.FSA;

public class FsaEngine
{
    private const string FamilyNeighbor = "neighbor_backup";
    private const string FamilyRs = "rs_coding";
    private const string FamilyEtn = "etn_validation";

    private static readonly Dictionary<string, string> FamilyMap = new()
    {
        { Constants.FssLevel1, FamilyNeighbor },
        { Constants.FssLevel2, FamilyNeighbor },
        { Constants.FssLevel2R, FamilyRs },
        { Constants.FssLevel3, FamilyRs },
        { Constants.FssLevel5, FamilyRs },
        { Constants.FssLevel5P, FamilyRs },
        { Constants.FssLevel6, FamilyEtn },
        { Constants.FssLevel61, FamilyEtn },
    };

    private static readonly Dictionary<string, List<string>> FamilyRank = new()
    {
        { FamilyNeighbor, new List<string> { Constants.FssLevel1, Constants.FssLevel2 } },
        { FamilyRs, new List<string> { Constants.FssLevel2R, Constants.FssLevel3, Constants.FssLevel5, Constants.FssLevel5P } },
        { FamilyEtn, new List<string> { Constants.FssLevel6, Constants.FssLevel61 } },
    };

    public FsaPlan Compute(string primary, List<string>? auxiliary = null)
    {
        var plan = new FsaPlan();

        var allStrategies = new List<string> { primary };
        if (auxiliary != null)
        {
            allStrategies.AddRange(auxiliary);
            if (!allStrategies.Contains(Constants.FssLevel6))
                allStrategies.Add(Constants.FssLevel6);
        }

        string primaryFamily = FamilyMap.GetValueOrDefault(primary, FamilyEtn);

        if (auxiliary != null)
        {
            foreach (string s in auxiliary)
            {
                string? sFamily = FamilyMap.GetValueOrDefault(s);
                if (sFamily != null && sFamily != primaryFamily && s != Constants.FssLevel6)
                {
                    throw new ArgumentException(
                        $"Cross-family fusion only supports FSS6 as auxiliary. " +
                        $"'{s}' ({sFamily}) cannot combine with '{primary}' ({primaryFamily}).");
                }
            }
        }

        var deduped = DedupWithinFamily(allStrategies);
        plan.ActiveStrategies = deduped;

        string effective = primary;
        if (!deduped.Contains(primary))
            effective = BestInFamily(deduped, primaryFamily) ?? primary;
        plan.EffectivePrimary = effective;

        var familiesInSet = new HashSet<string>();
        foreach (string s in deduped)
        {
            string? fam = FamilyMap.GetValueOrDefault(s);
            if (fam != null) familiesInSet.Add(fam);
        }
        plan.FamilyOrder = familiesInSet.ToList();
        var encodeSteps = new List<FsaStep>();
        encodeSteps.Add(new FsaStep
        {
            Step = "encode",
            Strategy = effective,
            Family = FamilyMap.GetValueOrDefault(effective, primaryFamily)
        });

        foreach (string s in deduped)
        {
            if (s == effective) continue;
            string fam = FamilyMap.GetValueOrDefault(s, FamilyEtn);
            if (s == Constants.FssLevel6 || s == Constants.FssLevel61)
            {
                encodeSteps.Add(new FsaStep { Step = "etn_inject", Strategy = Constants.FssLevel6, Family = FamilyEtn });
            }
            else
            {
                encodeSteps.Add(new FsaStep { Step = "encode", Strategy = s, Family = fam });
            }
        }
        plan.EncodeSteps = encodeSteps;

        var restore = new List<FsaStep>();
        bool hasFss6 = deduped.Contains(Constants.FssLevel6) || deduped.Contains(Constants.FssLevel61);
        if (hasFss6 && effective != Constants.FssLevel6)
        {
            restore.Add(new FsaStep { Step = "etn_strip", Strategy = Constants.FssLevel6, Family = FamilyEtn });
        }
        for (int i = encodeSteps.Count - 1; i >= 0; i--)
        {
            if (encodeSteps[i].Step == "encode")
            {
                restore.Add(new FsaStep { Step = "strip", Strategy = encodeSteps[i].Strategy, Family = encodeSteps[i].Family });
            }
        }
        plan.RestorePipeline = restore;
        plan.EstimatedOverhead = EstimateOverhead(deduped);
        plan.IsSingleStrategy = auxiliary == null || auxiliary.Count == 0;
        return plan;
    }

    private static List<string> DedupWithinFamily(List<string> strategies)
    {
        var families = new Dictionary<string, List<string>>();
        foreach (string s in strategies)
        {
            string? family = FamilyMap.GetValueOrDefault(s);
            if (family == null) continue;
            if (!families.ContainsKey(family))
                families[family] = new List<string>();
            families[family].Add(s);
        }
        var result = new List<string>();
        foreach (var (family, members) in families)
        {
            var ranked = FamilyRank.GetValueOrDefault(family, new List<string>());
            string? best = null;
            int bestIdx = -1;
            foreach (string m in members)
            {
                int idx = ranked.IndexOf(m);
                if (idx > bestIdx) { bestIdx = idx; best = m; }
            }
            if (best != null) result.Add(best);
        }
        return result;
    }

    private static string? BestInFamily(List<string> strategies, string family)
    {
        var ranked = FamilyRank.GetValueOrDefault(family, new List<string>());
        string? best = null;
        int bestIdx = -1;
        foreach (string s in strategies)
        {
            if (FamilyMap.GetValueOrDefault(s) == family && ranked.Contains(s))
            {
                int idx = ranked.IndexOf(s);
                if (idx > bestIdx) { bestIdx = idx; best = s; }
            }
        }
        return best;
    }

    private static double EstimateOverhead(List<string> strategies)
    {
        var overheads = new Dictionary<string, double>
        {
            { Constants.FssLevel1, 0.50 },
            { Constants.FssLevel2, 0.62 },
            { Constants.FssLevel2R, 0.86 },
            { Constants.FssLevel3, 0.86 },
            { Constants.FssLevel5, 2.00 },
            { Constants.FssLevel5P, 40.0 },
            { Constants.FssLevel6, 0.00008 },
            { Constants.FssLevel61, 0.05 },
        };
        var familiesSeen = new HashSet<string>();
        double total = 0.0;
        foreach (string s in strategies)
        {
            string? family = FamilyMap.GetValueOrDefault(s);
            if (family != null && !familiesSeen.Contains(family))
            {
                total += overheads.GetValueOrDefault(s, 0);
                familiesSeen.Add(family);
            }
        }
        if (familiesSeen.Contains(FamilyEtn) && strategies.Contains(Constants.FssLevel5P))
            total -= 4.0;
        return Math.Max(0, total);
    }
}

public class FsaPlan
{
    [JsonPropertyName("effective_primary")]
    public string EffectivePrimary { get; set; } = Constants.FssLevel1;

    [JsonPropertyName("active_strategies")]
    public List<string> ActiveStrategies { get; set; } = new();

    [JsonPropertyName("encode_steps")]
    public List<FsaStep> EncodeSteps { get; set; } = new();

    [JsonPropertyName("restore_pipeline")]
    public List<FsaStep> RestorePipeline { get; set; } = new();

    [JsonPropertyName("estimated_overhead")]
    public double EstimatedOverhead { get; set; }

    [JsonPropertyName("family_order")]
    public List<string> FamilyOrder { get; set; } = new();

    [JsonPropertyName("is_single_strategy")]
    public bool IsSingleStrategy { get; set; }
}

public class FsaStep
{
    [JsonPropertyName("step")]
    public string Step { get; set; } = string.Empty;

    [JsonPropertyName("strategy")]
    public string Strategy { get; set; } = string.Empty;

    [JsonPropertyName("family")]
    public string Family { get; set; } = string.Empty;
}

using RDRF.Core.FSA;

namespace RDRF.Core.Abstractions;

/// <summary>
/// Computes the FSA (Fragment Storage Architecture) plan for a given
/// combination of FSS strategies.
/// </summary>
public interface IFsaEngine
{
    /// <summary>
    /// Computes an <see cref="FsaPlan"/> that describes the encode/decode
    /// pipeline for one or more FSS strategies.
    /// </summary>
    /// <param name="primary">Primary FSS strategy (e.g. "FSS6.1").</param>
    /// <param name="auxiliary">Optional auxiliary strategies for multi-strategy fusion.</param>
    FsaPlan Compute(string primary, List<string>? auxiliary = null);
}

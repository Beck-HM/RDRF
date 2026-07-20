using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.Cuda;

namespace RDRF.Core.Device;

public static class GpuContext
{
    private static readonly object _lock = new();
    private static Context? _context;
    private static Accelerator? _accelerator;

    public static bool IsAvailable
    {
        get
        {
            try
            {
                EnsureInitialized();
                return _accelerator != null;
            }
            catch (System.IO.FileNotFoundException) { return false; }
            catch (System.DllNotFoundException) { return false; }
            catch { return false; }
        }
    }

    public static Accelerator Accelerator
    {
        get
        {
            EnsureInitialized();
            return _accelerator ?? throw new PlatformNotSupportedException("No GPU accelerator available.");
        }
    }

    public static Context Context
    {
        get
        {
            EnsureInitialized();
            return _context!;
        }
    }

    private static void EnsureInitialized()
    {
        if (_context != null) return;
        lock (_lock)
        {
            if (_context != null) return;

            _context = Context.Create(builder => builder.Default().EnableAlgorithms());

            try
            {
                _accelerator = _context.CreateCudaAccelerator(0);
            }
            catch
            {
                _accelerator = null;
            }
        }
    }

    public static void Dispose()
    {
        lock (_lock)
        {
            _accelerator?.Dispose();
            _context?.Dispose();
            _accelerator = null;
            _context = null;
        }
    }
}

namespace RDRF.Core;

public enum ErrorSeverity { Warning, Error, Fatal }

public enum ErrorCode
{
    Unknown,
    PasswordInvalid,
    FileNotFound,
    FileTooLarge,
    FileFormatInvalid,
    IndexCorrupted,
    FragmentMissing,
    FragmentDecryptFailed,
    IntegrityCheckFailed,
    HashMismatch,
    StorageBackendUnavailable,
    StorageBackendNotConfigured,
    StorageWriteFailed,
    StorageReadFailed,
    OperationTimedOut,
    OperationCancelled,
    UnsupportedPlatform,
    UnsupportedStrategy,
    CompressionFailed,
    DecompressionFailed,
    FssRecoveryFailed,
    FssEncodingFailed,
    VersionNotFound,
    VersionConflict,
    PathTraversal,
    ConfigInvalid,
    ResourceExhausted,
    InternalError,
}

public class RdrfException : System.Exception
{
    public ErrorCode Code { get; }
    public ErrorSeverity Severity { get; }

    public RdrfException(ErrorCode code, string message, ErrorSeverity severity = ErrorSeverity.Error)
        : base(message)
    {
        Code = code;
        Severity = severity;
    }

    public RdrfException(ErrorCode code, string message, System.Exception inner, ErrorSeverity severity = ErrorSeverity.Error)
        : base(message, inner)
    {
        Code = code;
        Severity = severity;
    }
}

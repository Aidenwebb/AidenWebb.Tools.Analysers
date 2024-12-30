namespace AidenWebb.Tools.Analysers.Spf;

public class SpfErrorDetail
{
    /// <summary>
    /// A short code or enum that identifies this error type.
    /// </summary>
    public string Code { get; set; }

    /// <summary>
    /// Human-readable error message, possibly localizable.
    /// </summary>
    public string Message { get; set; }

    /// <summary>
    /// If applicable, the index of the token or term 
    /// that caused this error. (Optional)
    /// </summary>
    public int? TermIndex { get; set; }

    /// <summary>
    /// The raw SPF term that caused the error (Optional).
    /// </summary>
    public string? TermValue { get; set; }
    
    /// <summary>
    /// A classification or severity (Warning, Error, etc.).
    /// </summary>
    public SpfErrorSeverity Severity { get; set; } = SpfErrorSeverity.Error;
}

public enum SpfErrorSeverity
{
    Error,
    Warning,
    Info
}

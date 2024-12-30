namespace AidenWebb.Tools.Analysers.Spf;

public enum SpfQualifier
{
    /// <summary>
    /// Indicates that no SPF record was found for this domain 
    /// (or that the record was not applicable).
    /// </summary>
    None,
    
    /// <summary>
    /// Email message passes authentication, indicating the server is authorized 
    /// to send on behalf of the domain (often represented by '+' or no qualifier).
    /// </summary>
    Pass,
    
    /// <summary>
    /// Email message fails authentication (represented by '-') because the 
    /// sending server is not authorized to send on behalf of the domain.
    /// </summary>
    Fail,
    
    /// <summary>
    /// The server is not authorized to send on behalf of the domain (represented by '~'), 
    /// but the receiving server should accept the message (often marking it as spam).
    /// </summary>
    SoftFail,
    
    /// <summary>
    /// Neither passes nor fails authentication (represented by '?'). 
    /// Indicates the domain does not assert a definitive policy for this sender.
    /// </summary>
    Neutral,
}
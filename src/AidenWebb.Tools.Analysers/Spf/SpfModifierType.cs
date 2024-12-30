namespace AidenWebb.Tools.Analysers.Spf;

public enum SpfModifierType
{
    /// <summary>
    /// Unknown Modifier
    /// </summary>
    Unknown,
    /// <summary>
    /// The 'redirect=' modifier, which instructs that if this SPF record does not 
    /// result in a definitive match, the evaluation should continue with the SPF record 
    /// of the domain specified in the redirect.
    /// </summary>
    Redirect,
    /// <summary>
    /// The 'exp=' modifier, which specifies a domain name whose TXT record 
    /// provides an explanation in case of a failed authentication.
    /// </summary>
    Exp
}
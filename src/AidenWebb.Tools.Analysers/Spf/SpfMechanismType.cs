namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
/// Types of SPF Mechanisms
/// </summary>
public enum SpfMechanismType
{
    /// <summary>
    /// Unknown Mechanism
    /// </summary>
    Unknown,
    /// <summary>
    /// ALL Mechanism, always matches, must be at the end of the record
    /// </summary>
    /// <example>
    /// For example: "v=spf1 include:_spf.google.com -all"
    /// </example>
    All,
    /// <summary>
    /// IP4 Mechanism, matches if the IP V4 address is within the given network
    /// </summary>
    Ip4,
    /// <summary>
    /// IP6 Mechanism, matches if IP V6 address is within the given network
    /// </summary>
    Ip6,
    /// <summary>
    /// A mechanism, matches if the IP address is the target of a hostname lookup for the given domain
    /// </summary>
    A,
    /// <summary>
    /// MX mechanism, matches if the IP address is a Mail Exchanger for the given domain
    /// </summary>
    Mx,
    /// <summary>
    /// PTR Mechanism, matches if a correct reverse mapping exists
    /// </summary>
    Ptr,
    /// <summary>
    /// EXISTS Mechanism, matches if the given domain exists
    /// </summary>
    Exists,
    /// <summary>
    /// INCLUDE Mechanism, which triggers a recursive evaluation
    /// </summary>
    Include
}
using System.Text;

namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
///   Represents a single modifier term in a SPF record
/// </summary>
public class SpfModifier : SpfTerm
{
    /// <summary>
    ///   Type of the modifier
    /// </summary>
    public SpfModifierType Type { get; }

    /// <summary>
    ///   The Host part of the modifier
    /// </summary>
    public string Host { get; }

    /// <summary>
    ///   Creates a new instance of the SpfModifier
    /// </summary>
    /// <param name="type">Type of the modifier</param>
    /// <param name="host">Domain part of the modifier</param>
    public SpfModifier(SpfModifierType type, string host)
    {
        Type = type;
        Host = host;
    }

    /// <summary>
    ///   Returns the textual representation of a modifier term
    /// </summary>
    /// <returns> Textual representation </returns>
    public override string ToString()
    {
        StringBuilder res = new StringBuilder();

        res.Append(EnumHelper<SpfModifierType>.ToString(Type).ToLowerInvariant());
        res.Append("=");
        res.Append(Host);

        return res.ToString();
    }
}
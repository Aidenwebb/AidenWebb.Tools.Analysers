using System.Text;

namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
/// Base class for representing an SPF record. 
/// Contains the raw SPF string (often beginning with "v=spf1") that can be parsed 
/// into mechanisms, qualifiers, and modifiers.
/// </summary>
public abstract class SpfRecordBase
{
    public List<SpfTerm> Terms { get; }

    protected SpfRecordBase(List<SpfTerm> terms)
    {
        Terms = terms;
    }
    
    /// <summary>
    ///   Returns the textual representation of a SPF record
    /// </summary>
    /// <returns> Textual representation </returns>
    public override string ToString()
    {
        StringBuilder res = new StringBuilder();
        res.Append("v=spf1");

        if ((Terms != null) && (Terms.Count > 0))
        {
            foreach (SpfTerm term in Terms)
            {
                SpfModifier? modifier = term as SpfModifier;
                if ((modifier == null) || (modifier.Type != SpfModifierType.Unknown))
                {
                    res.Append(" ");
                    res.Append(term);
                }
            }
        }

        return res.ToString();
    }
    /// <summary>
    ///   Checks, whether a given string starts with a correct SPF prefix
    /// </summary>
    /// <param name="s"> Textual representation to check </param>
    /// <returns> true in case of correct prefix </returns>
    public static bool IsSpfRecord(string s)
    {
        return !String.IsNullOrEmpty(s) && s.StartsWith("v=spf1 ");
    }

    /// <summary>
    ///   Tries to parse the textual representation of a SPF string
    /// </summary>
    /// <param name="s"> Textual representation to check </param>
    /// <param name="value"> Parsed spf record in case of successful parsing </param>
    /// <returns> true in case of successful parsing </returns>
    public static bool TryParse(string s, out SpfRecord? value)
    {
        if (!IsSpfRecord(s))
        {
            value = null;
            return false;
        }

        string[] terms = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

        List<SpfTerm>? parsedTerms;
        if (TryParseTerms(terms, out parsedTerms))
        {
            value = new SpfRecord(parsedTerms!);
            return true;
        }
        else
        {
            value = null;
            return false;
        }
    }
    protected static bool TryParseTerms(string[] terms, out List<SpfTerm>? parsedTerms)
    {
        parsedTerms = new List<SpfTerm>(terms.Length - 1);

        for (int i = 1; i < terms.Length; i++)
        {
            SpfTerm? term;
            if (SpfTerm.TryParse(terms[i], out term))
            {
                parsedTerms.Add(term!);
            }
            else
            {
                parsedTerms = null;
                return false;
            }
        }

        return true;
    }
}
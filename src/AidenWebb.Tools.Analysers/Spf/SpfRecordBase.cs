namespace AidenWebb.Tools.Analysers.Spf;

/// <summary>
/// Base class for representing an SPF record. 
/// Contains the raw SPF string (often beginning with "v=spf1") that can be parsed 
/// into mechanisms, qualifiers, and modifiers.
/// </summary>
public abstract class SpfRecordBase
{
    public string RecordText { get; set; }
    
    public List<SpfTerm> Terms { get; }

    protected SpfRecordBase(List<SpfTerm> terms)
    {
        Terms = terms;
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
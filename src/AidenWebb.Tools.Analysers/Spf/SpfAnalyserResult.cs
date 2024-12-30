namespace AidenWebb.Tools.Analysers.Spf;

public class SpfAnalyserResult
{
    public string RecordText { get; set; }
    public SpfRecord SpfRecord { get; set; }
    public bool RecordIsValid { get; set; }
    public SpfQualifier MechanismFailureMode { get; set; }
    public int DnsLookupCount { get; set; }
    public bool DnsLookupCountBelowTen => DnsLookupCount < 10;
    public int VoidLookupCount {get;set;}
    public bool VoidLookupCountBelowTwo => VoidLookupCount < 2;
    public List<SpfErrorDetail> Errors { get; set; } = new();

}
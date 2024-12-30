using AidenWebb.Tools.Analysers.Spf;

namespace AidenWebb.Tools.Analysers.Tests.Systems;

public class SpfAnalyserTests
{
    [Fact]
    public void SpfParser_CorrectlyParses_ValidRecord()
    {
        // Arrange
        SpfRecord? spfRecord;
        var recordText =
            "v=spf1 include:spf.protection.outlook.com include:spf.mtasv.net include:spf.uk.exclaimer.net include:sendgrid.net ip4:104.21.71.145/32 include:spf.sendinblue.com mx -all"; 
        
        // Act
        SpfRecord.TryParse(
            recordText,
            out spfRecord);

        // Assert
        Assert.NotNull(spfRecord);
        Assert.NotEmpty(spfRecord.Terms);
        Assert.Equal(recordText, spfRecord.ToString());
    }

    [Fact]
    public async Task SpfAnalyser_CorrectlyCounts_DnsLookups()
    {
        // Arrange
        SpfRecord? spfRecord;
        var recordText =
            "v=spf1 include:spf.protection.outlook.com include:spf.mtasv.net include:spf.uk.exclaimer.net include:sendgrid.net ip4:104.21.71.145/32 include:spf.sendinblue.com mx -all"; 
        
        SpfRecord.TryParse(
            recordText,
            out spfRecord);

        var Analyser = new SpfAnalyser();

        // Act

        var analysisResult = await Analyser.AnalyseAsync(spfRecord);
        
        // Assert
        Assert.NotNull(spfRecord);
        Assert.NotEmpty(spfRecord.Terms);
        Assert.Equal(recordText,analysisResult.RecordText);
        Assert.Equal(7,analysisResult.DnsLookupCount);
    }
}
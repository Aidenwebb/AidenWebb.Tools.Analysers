using AidenWebb.Tools.Analysers.Spf;

namespace AidenWebb.Tools.Analysers.Tests.Systems;

public class SpfAnalyserTests
{
    [Fact]
    public void SpfParser_CorrectlyParses_ValidRecord()
    {
        // Arrange
        SpfRecord? spfRecord;
        
        // Act
        SpfRecord.TryParse(
            "v=spf1 include:spf.protection.outlook.com include:spf.mtasv.net include:spf.uk.exclaimer.net include:sendgrid.net ip4:104.21.71.145/32 include:spf.sendinblue.com mx -all",
            out spfRecord);

        // Assert
        Assert.NotNull(spfRecord);
        Assert.NotEmpty(spfRecord.Terms);
    }
}
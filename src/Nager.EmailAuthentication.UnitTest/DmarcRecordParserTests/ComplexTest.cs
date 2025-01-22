namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ComplexTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("100", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("s", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("s", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

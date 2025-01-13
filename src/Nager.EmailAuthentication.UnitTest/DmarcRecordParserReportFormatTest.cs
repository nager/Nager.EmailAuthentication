namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserReportFormatTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; rf=afrf", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("afrf", dmarcDataFragment.ReportFormat);
            Assert.IsNull(parseErrors, "ParseErrors is not null"); ;
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; rf=afrf1", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("afrf1", dmarcDataFragment.ReportFormat);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; rf=", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("", dmarcDataFragment.ReportFormat);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }
    }
}

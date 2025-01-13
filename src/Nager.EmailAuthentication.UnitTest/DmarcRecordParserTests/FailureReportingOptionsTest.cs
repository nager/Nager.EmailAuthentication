namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class FailureReportingOptionsTest
    {
        [DataRow("0")]
        [DataRow("1")]
        [DataRow("d")]
        [DataRow("s")]
        [DataTestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord(string failureReportingOptions)
        {
            var isSuccessful = DmarcRecordParser.TryParse($"v=DMARC1; p=reject; fo={failureReportingOptions}", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual(failureReportingOptions, dmarcDataFragment.FailureReportingOptions);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [DataRow("a")]
        [DataRow("b")]
        [DataRow("8")]
        [DataRow("9")]
        [DataTestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors(string failureReportingOptions)
        {
            var isSuccessful = DmarcRecordParser.TryParse($"v=DMARC1; p=reject; fo={failureReportingOptions}", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual(failureReportingOptions, dmarcDataFragment.FailureReportingOptions);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }
    }
}

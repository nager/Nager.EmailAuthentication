namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class FailureReportingOptionsTest
    {
        [DataRow("0")]
        [DataRow("1")]
        [DataRow("d")]
        [DataRow("s")]
        [DataRow("s:d")]
        [DataRow("s:d:1")]
        [DataTestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord(string failureReportingOptions)
        {
            var isSuccessful = DmarcRecordParser.TryParse($"v=DMARC1; p=reject; fo={failureReportingOptions}", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual(failureReportingOptions, dmarcDataFragment.FailureReportingOptions);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [DataRow("a", 2)]
        [DataRow("b", 2)]
        [DataRow("8", 2)]
        [DataRow("9", 2)]
        [DataRow("wrong", 2)]
        [DataRow("s:x:dd", 3)]
        [DataTestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors(string failureReportingOptions, int parsingResultsCount)
        {
            var isSuccessful = DmarcRecordParser.TryParse($"v=DMARC1; p=reject; fo={failureReportingOptions}", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual(failureReportingOptions, dmarcDataFragment.FailureReportingOptions);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == parsingResultsCount);
        }
    }
}

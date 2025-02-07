namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ReportingIntervalTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=86400;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("86400", dmarcDataFragment.ReportingInterval);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=1000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("1000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=1000000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("1000000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=-1000000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("-1000000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }
    }
}

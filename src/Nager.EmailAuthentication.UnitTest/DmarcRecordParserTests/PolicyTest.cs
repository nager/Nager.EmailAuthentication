namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class PolicyTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=Test", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
            Assert.IsNotNull(parsingResults);
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=Test;", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
            Assert.IsNotNull(parsingResults);
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=reject;", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=reject; sp=none;", out var dmarcDataFragment, out var parsingResults);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("none", dmarcDataFragment.SubdomainPolicy);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

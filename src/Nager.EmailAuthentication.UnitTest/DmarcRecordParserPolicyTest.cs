namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserPolicyTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
            Assert.IsNotNull(parseErrors);
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
            Assert.IsNotNull(parseErrors);
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_ValidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; sp=none;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("none", dmarcDataFragment.SubdomainPolicy);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }
    }
}

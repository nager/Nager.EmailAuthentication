namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserPolicyPercentageTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; pct=60;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("60", dmarcDataFragment.PolicyPercentage);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; pct=;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("", dmarcDataFragment.PolicyPercentage);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; pct=200;", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("200", dmarcDataFragment.PolicyPercentage);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
        }
    }
}

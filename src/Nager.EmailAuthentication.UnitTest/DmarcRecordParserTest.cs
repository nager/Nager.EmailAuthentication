namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
            Assert.IsNotNull(parseErrors);
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString4_ReturnsTrueAndPopulatesDmarcRecord()
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

        [TestMethod]
        public void TryParse_ValidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("100", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("s", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("s", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString1_ReturnsTrueAndParseErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("verification=123456789", out var dmarcDataFragment, out var parseErrors);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 2);
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString2_ReturnsFalse()
        {
            var isSuccessful = DmarcRecordParser.TryParse(" ", out var dmarcDataFragment, out var parseErrors);
            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dmarcDataFragment);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString3_ReturnsTrueWithErrors()
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

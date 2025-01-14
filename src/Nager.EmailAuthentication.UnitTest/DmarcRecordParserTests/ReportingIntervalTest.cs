namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ReportingIntervalTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; ri=86400;", out var dmarcDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("86400", dmarcDataFragment.ReportingInterval);
            Assert.IsNull(parseErrors, "ParseErrors is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; ri=1000;", out var dmarcDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("1000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; ri=1000000;", out var dmarcDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("1000000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=reject; ri=-1000000;", out var dmarcDataFragment, out var parseErrors);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("-1000000", dmarcDataFragment.ReportingInterval);
            Assert.IsNotNull(parseErrors, "ParseErrors is null");
            Assert.IsTrue(parseErrors.Length == 1);
        }
    }
}

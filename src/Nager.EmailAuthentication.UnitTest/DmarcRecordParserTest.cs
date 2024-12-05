namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC", out var dmarcDataFragment);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1", out var dmarcDataFragment);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test", out var dmarcDataFragment);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString4_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test;", out var dmarcDataFragment);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("Test", dmarcDataFragment.DomainPolicy);
        }
    }
}

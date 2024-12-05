namespace Nager.MailAuth.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC", out var dmarcRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1", out var dmarcRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test", out var dmarcRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);
            Assert.AreEqual("Test", dmarcRecord.DomainPolicy);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString4_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC1; p=Test;", out var dmarcRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);
            Assert.AreEqual("Test", dmarcRecord.DomainPolicy);
        }
    }
}

namespace Nager.MailAuth.UnitTest
{
    [TestClass]
    public sealed class DmarcRecordParserTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordParser.TryParse("v=DMARC", out var dmarcRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);
        }
    }
}

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class BasicTest
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
        public void TryParse_CorruptDmarcString1_ReturnsFalseAndParseErrors()
        {
            var isSuccessful = DmarcRecordParser.TryParse("verification=123456789", out var dmarcDataFragment, out var parseErrors);

            Assert.IsFalse(isSuccessful);
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
    }
}

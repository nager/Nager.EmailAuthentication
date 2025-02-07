namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString1_ReturnsFalseAndParseErrors()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("verification=123456789", out var dmarcDataFragment, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString2_ReturnsFalse()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(" ", out var dmarcDataFragment, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dmarcDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

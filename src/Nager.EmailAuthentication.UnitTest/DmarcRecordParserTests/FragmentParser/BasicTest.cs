using Nager.EmailAuthentication.FragmentParsers;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.FragmentParser
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString1_ReturnsFalseAndParseErrors()
        {
            var recordRaw = "verification=123456789";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_CorruptDmarcString2_ReturnsFalse()
        {
            var recordRaw = " ";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

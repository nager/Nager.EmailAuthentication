using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.FragmentParser
{
    [TestClass]
    public sealed class ReportFormatTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rf=afrf";

            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("afrf", dataFragmentV1.ReportFormat);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors()
        {
            var recordRaw = "v=DMARC1; p=reject; rf=afrf1";

            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("afrf1", dataFragmentV1.ReportFormat);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors()
        {
            var recordRaw = "v=DMARC1; p=reject; rf=";

            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("", dataFragmentV1.ReportFormat);

        }
    }
}

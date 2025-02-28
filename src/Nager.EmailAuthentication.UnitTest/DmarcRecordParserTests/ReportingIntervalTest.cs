using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ReportingIntervalTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=86400;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("86400", dataFragmentV1.ReportingInterval);

        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=1000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out var parsingResults);

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
            Assert.AreEqual("1000", dataFragmentV1.ReportingInterval);

        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=1000000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out var parsingResults);

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
            Assert.AreEqual("1000000", dataFragmentV1.ReportingInterval);

        }

        [TestMethod]
        public void TryParse_InvalidDmarcString3_ReturnsTrueWithErrors()
        {
            var dmarcRaw = "v=DMARC1; p=reject; ri=-1000000;";
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRaw, out var dataFragment, out var parsingResults);

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
            Assert.AreEqual("-1000000", dataFragmentV1.ReportingInterval);

        }
    }
}

using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models.Dmarc;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.FragmentParser
{
    [TestClass]
    public sealed class PolicyPercentageTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; pct=60;";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("60", dataFragmentV1.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var recordRaw = "v=DMARC1; p=reject; pct=;";
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
            Assert.AreEqual("", dataFragmentV1.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var recordRaw = "v=DMARC1; p=reject; pct=200;";
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
            Assert.AreEqual("200", dataFragmentV1.PolicyPercentage);
        }
    }
}

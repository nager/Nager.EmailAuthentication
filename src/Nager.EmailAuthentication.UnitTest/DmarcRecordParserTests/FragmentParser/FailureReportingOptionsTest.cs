using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models.Dmarc;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.FragmentParser
{
    [TestClass]
    public sealed class FailureReportingOptionsTest
    {
        [DataRow("0")]
        [DataRow("1")]
        [DataRow("d")]
        [DataRow("s")]
        [DataRow("s:d")]
        [DataRow("s:d:1")]
        [DataTestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord(string failureReportingOptions)
        {
            var recordRaw = $"v=DMARC1; p=reject; fo={failureReportingOptions}";

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
            Assert.AreEqual(failureReportingOptions, dataFragmentV1.FailureReportingOptions);
        }

        [DataRow("a", 2)]
        [DataRow("b", 2)]
        [DataRow("8", 2)]
        [DataRow("9", 2)]
        [DataRow("wrong", 2)]
        [DataRow("s:x:dd", 3)]
        [DataTestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecordWithParseErrors(string failureReportingOptions, int parsingResultsCount)
        {
            var recordRaw = $"v=DMARC1; p=reject; fo={failureReportingOptions}";

            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == parsingResultsCount);

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual(failureReportingOptions, dataFragmentV1.FailureReportingOptions);
        }
    }
}

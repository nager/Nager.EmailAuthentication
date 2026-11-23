using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.FragmentParser
{
    /// <summary>
    /// Tags added by RFC 9989 (DMARCbis)
    /// </summary>
    [TestClass]
    public sealed class Rfc9989Test
    {
        [TestMethod]
        public void TryParse_NewTags_ReturnsTrueAndPopulatesDataFragment()
        {
            var recordRaw = "v=DMARC1; p=reject; np=quarantine; t=y; psd=n";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            Assert.AreEqual("reject", dataFragment.DomainPolicy);
            Assert.AreEqual("quarantine", dataFragment.NonExistentSubdomainPolicy);
            Assert.AreEqual("y", dataFragment.TestMode);
            Assert.AreEqual("n", dataFragment.PublicSuffixDomain);
            Assert.AreEqual("v=DMARC1; p=reject; np=quarantine; t=y; psd=n;", dataFragment.ToString());
        }

        [DataRow("np", "invalid")]
        [DataRow("t", "yes")]
        [DataRow("t", "")]
        [DataRow("psd", "x")]
        [DataRow("psd", "")]
        [TestMethod]
        public void TryParse_InvalidValueOfNewTag_ReturnsTrueWithError(string tag, string value)
        {
            var recordRaw = $"v=DMARC1; p=reject; {tag}={value}";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(tag, parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
        }

        [TestMethod]
        public void TryParse_VersionInLowerCase_ReturnsTrueWithCriticalError()
        {
            var recordRaw = "v=dmarc1; p=reject";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(ParsingStatus.Critical, parsingResults[0].Status);
        }

        [TestMethod]
        public void TryParse_WhitespaceAroundEqualSign_ReturnsTrueAndPopulatesDataFragment()
        {
            var recordRaw = "v = DMARC1 ; p = reject ; sp = none";
            var isSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            Assert.AreEqual("DMARC1", dataFragment.Version);
            Assert.AreEqual("reject", dataFragment.DomainPolicy);
            Assert.AreEqual("none", dataFragment.SubdomainPolicy);
        }
    }
}

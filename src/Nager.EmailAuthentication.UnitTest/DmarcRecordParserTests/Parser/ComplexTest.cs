using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dmarc;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.Parser
{
    [TestClass]
    public sealed class ComplexTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

            var isSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcRecord);

            // The pct tag is obsolete (RFC 9989)
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual("pct", parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Warning, parsingResults[0].Status);

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.DomainPolicy);
            //Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcRecordV1.AggregateReportUri);
            Assert.AreEqual(100, dmarcRecordV1.PolicyPercentage);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecordV1.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecordV1.SpfAlignmentMode);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com!10m, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord);

            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(dmarcRecord);

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordV1 class");
                return;
            }

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.SubdomainPolicy);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecordV1.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecordV1.SpfAlignmentMode);
            Assert.AreEqual(100, dmarcRecordV1.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=r; aspf=r";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord);

            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(dmarcRecord);

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordV1 class");
                return;
            }

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.SubdomainPolicy);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecordV1.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecordV1.SpfAlignmentMode);
            Assert.AreEqual(50, dmarcRecordV1.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcStringInvalidValueAdkimAndAspf_ReturnsTrueWithDefaultValues()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; adkim=t; aspf=t";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord, out var parsingResults);

            // A tag with an invalid value is ignored in favor of its default value (RFC 9989 section 4.8)
            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(2, parsingResults.Length);
            Assert.IsTrue(parsingResults.All(o => o.Status == ParsingStatus.Error));

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordV1 class");
                return;
            }

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecordV1.DomainPolicy);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecordV1.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecordV1.SpfAlignmentMode);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcStringNoValueAfterExclamationMark_ReturnsTrueWithoutReportUri()
        {
            var recordRaw = "v=DMARC1; p=none; rua=mailto:postmaster@example.com!";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord, out var parsingResults);

            // The policy is still applied, the invalid report URI is ignored
            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual("rua", parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordV1 class");
                return;
            }

            Assert.AreEqual(DmarcPolicy.None, dmarcRecordV1.DomainPolicy);
            Assert.IsNull(dmarcRecordV1.AggregateReportUri);
        }

        //

        [DataRow(1)]
        [DataRow(2)]
        [DataRow(3)]
        [DataRow(10)]
        [DataRow(100)]
        [TestMethod]
        public void TryParse_InvalidDmarcStringInvalidPolicy_ReturnFalse(int value)
        {
            var recordRaw = $"v=DMARC1; p={value};";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
        }
    }
}

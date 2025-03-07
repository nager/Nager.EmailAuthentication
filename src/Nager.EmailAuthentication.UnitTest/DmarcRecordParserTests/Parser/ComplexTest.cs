using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;

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
            Assert.IsNull(parsingResults, "ParsingResults is not null");

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
        public void TryParse_InvalidDmarcStringInvalidValueAdkimAndAspf_ReturnFalse()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=t; aspf=t";

            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
        }
    }
}

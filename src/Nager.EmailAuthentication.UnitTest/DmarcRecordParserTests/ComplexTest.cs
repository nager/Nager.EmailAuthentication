using Nager.EmailAuthentication.FragmentParsers;
using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ComplexTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

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
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dataFragmentV1.AggregateReportUri);
            Assert.AreEqual("100", dataFragmentV1.PolicyPercentage);
            Assert.AreEqual("s", dataFragmentV1.DkimAlignmentMode);
            Assert.AreEqual("s", dataFragmentV1.SpfAlignmentMode);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com!10m, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com!10m, mailto:dmarc@example.com", dataFragmentV1.AggregateReportUri);
            Assert.AreEqual("100", dataFragmentV1.PolicyPercentage);
            Assert.AreEqual("s", dataFragmentV1.DkimAlignmentMode);
            Assert.AreEqual("s", dataFragmentV1.SpfAlignmentMode);

            var isParserSuccessful = DmarcRecordParser.TryParseV1(dataFragmentV1, out var dmarcRecord);

            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(dmarcRecord);

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecord.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecord.SpfAlignmentMode);
            Assert.AreEqual(100, dmarcRecord.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_ValidDmarcString3_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=r; aspf=r";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dataFragmentV1.AggregateReportUri);
            Assert.AreEqual("50", dataFragmentV1.PolicyPercentage);
            Assert.AreEqual("r", dataFragmentV1.DkimAlignmentMode);
            Assert.AreEqual("r", dataFragmentV1.SpfAlignmentMode);


            var isParserSuccessful = DmarcRecordParser.TryParseV1(dataFragmentV1, out var dmarcRecord);

            Assert.IsTrue(isParserSuccessful);
            Assert.IsNotNull(dmarcRecord);

            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecord.DkimAlignmentMode);
            Assert.AreEqual(AlignmentMode.Relaxed, dmarcRecord.SpfAlignmentMode);
            Assert.AreEqual(50, dmarcRecord.PolicyPercentage);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var recordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=t; aspf=t";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParserV1.TryParse(recordRaw, out var dataFragment, out var parsingResults);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");

            if (dataFragment is not DmarcRecordDataFragmentV1 dataFragmentV1)
            {
                Assert.Fail("Wrong DmarcRecordDataFragmentV1 class");
                return;
            }

            Assert.AreEqual("reject", dataFragmentV1.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dataFragmentV1.AggregateReportUri);
            Assert.AreEqual("50", dataFragmentV1.PolicyPercentage);
            Assert.AreEqual("t", dataFragmentV1.DkimAlignmentMode);
            Assert.AreEqual("t", dataFragmentV1.SpfAlignmentMode);

            var isParserSuccessful = DmarcRecordParser.TryParseV1(dataFragmentV1, out var dmarcRecord);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
        }
    }
}

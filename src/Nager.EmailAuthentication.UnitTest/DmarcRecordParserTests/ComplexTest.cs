using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class ComplexTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRecord = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

            var isSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRecord, out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("100", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("s", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("s", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_ValidDmarcString2_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRecordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com!10m, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRecordRaw, out var dmarcDataFragment, out var parsingResults);
            Assert.IsNotNull(dmarcDataFragment);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com!10m, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("100", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("s", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("s", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            var isParserSuccessful = DmarcRecordParser.TryParse(dmarcDataFragment, out var dmarcRecord);
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
            var dmarcRecordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=r; aspf=r";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRecordRaw, out var dmarcDataFragment, out var parsingResults);
            Assert.IsNotNull(dmarcDataFragment);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("50", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("r", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("r", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNull(parsingResults, "ParsingResults is not null");

            var isParserSuccessful = DmarcRecordParser.TryParse(dmarcDataFragment, out var dmarcRecord);
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
            var dmarcRecordRaw = "v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=50; adkim=t; aspf=t";

            var isDataFragmentParserSuccessful = DmarcRecordDataFragmentParser.TryParse(dmarcRecordRaw, out var dmarcDataFragment, out var parsingResults);
            Assert.IsNotNull(dmarcDataFragment);

            Assert.IsTrue(isDataFragmentParserSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("mailto:postmaster@example.com, mailto:dmarc@example.com", dmarcDataFragment.AggregateReportUri);
            Assert.AreEqual("50", dmarcDataFragment.PolicyPercentage);
            Assert.AreEqual("t", dmarcDataFragment.DkimAlignmentMode);
            Assert.AreEqual("t", dmarcDataFragment.SpfAlignmentMode);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");

            var isParserSuccessful = DmarcRecordParser.TryParse(dmarcDataFragment, out var dmarcRecord);
            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
        }
    }
}

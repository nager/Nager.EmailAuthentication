using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dmarc;

namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests.Parser
{
    /// <summary>
    /// Behavior defined by RFC 9989 (DMARCbis), which obsoletes RFC 7489
    /// </summary>
    [TestClass]
    public sealed class Rfc9989Test
    {
        private static DmarcRecordV1 Parse(string recordRaw, out ParsingResult[]? parsingResults)
        {
            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord, out parsingResults);

            Assert.IsTrue(isParserSuccessful);

            if (dmarcRecord is not DmarcRecordV1 dmarcRecordV1)
            {
                Assert.Fail("Wrong DmarcRecordV1 class");
                return null!;
            }

            return dmarcRecordV1;
        }

        [TestMethod]
        public void TryParse_NewTags_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject; sp=quarantine; np=none; t=y; psd=n; rua=mailto:dmarc@example.com", out var parsingResults);

            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.Quarantine, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.NonExistentSubdomainPolicy);
            Assert.IsTrue(dmarcRecord.TestMode);
            Assert.AreEqual(PublicSuffixDomainMode.No, dmarcRecord.PublicSuffixDomain);
        }

        [TestMethod]
        public void TryParse_WithoutNewTags_UsesDefaultValues()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject", out var parsingResults);

            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.NonExistentSubdomainPolicy);
            Assert.IsFalse(dmarcRecord.TestMode);
            Assert.AreEqual(PublicSuffixDomainMode.Unknown, dmarcRecord.PublicSuffixDomain);
        }

        [TestMethod]
        public void TryParse_SubdomainPolicyWithoutNonExistentSubdomainPolicy_UsesSubdomainPolicy()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject; sp=none", out _);

            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.NonExistentSubdomainPolicy);
        }

        [DataRow("y", PublicSuffixDomainMode.Yes)]
        [DataRow("n", PublicSuffixDomainMode.No)]
        [DataRow("u", PublicSuffixDomainMode.Unknown)]
        [TestMethod]
        public void TryParse_PublicSuffixDomain_ReturnsMode(string value, PublicSuffixDomainMode expectedMode)
        {
            var dmarcRecord = Parse($"v=DMARC1; p=reject; psd={value}", out var parsingResults);

            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(expectedMode, dmarcRecord.PublicSuffixDomain);
        }

        [DataRow("t", "x")]
        [DataRow("t", "")]
        [DataRow("psd", "x")]
        [TestMethod]
        public void TryParse_InvalidValueOfNewTag_ReturnsTrueWithDefaultValueAndError(string tag, string value)
        {
            var dmarcRecord = Parse($"v=DMARC1; p=reject; {tag}={value}", out var parsingResults);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(tag, parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
            Assert.IsFalse(dmarcRecord.TestMode);
            Assert.AreEqual(PublicSuffixDomainMode.Unknown, dmarcRecord.PublicSuffixDomain);
        }

        [DataRow("pct", "50")]
        [DataRow("pct", "abc")]
        [DataRow("pct", "200")]
        [DataRow("ri", "86400")]
        [DataRow("ri", "abc")]
        [DataRow("rf", "afrf")]
        [DataRow("rf", "iodef")]
        [TestMethod]
        public void TryParse_ObsoleteTag_ReturnsTrueWithWarning(string tag, string value)
        {
            var dmarcRecord = Parse($"v=DMARC1; p=reject; {tag}={value}", out var parsingResults);

            // The tags were removed by RFC 9989, an invalid value does not affect the record
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(tag, parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Warning, parsingResults[0].Status);
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
        }

        [DataRow("v=DMARC1; rua=mailto:dmarc@example.com", "p")]
        [DataRow("v=DMARC1; p=invalid; rua=mailto:dmarc@example.com", "p")]
        [DataRow("v=DMARC1; p=reject; sp=invalid; rua=mailto:dmarc@example.com", "sp")]
        [DataRow("v=DMARC1; p=reject; np=invalid; rua=mailto:dmarc@example.com", "np")]
        [TestMethod]
        public void TryParse_NoValidPolicyWithReportUri_IsTreatedLikePolicyNone(string recordRaw, string invalidTag)
        {
            var dmarcRecord = Parse(recordRaw, out var parsingResults);

            // RFC 9989 section 4.10.1
            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.DomainPolicy);
            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.SubdomainPolicy);
            Assert.AreEqual(DmarcPolicy.None, dmarcRecord.NonExistentSubdomainPolicy);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Any(o => o.Field == invalidTag && o.Status == ParsingStatus.Error && o.Message.Contains("p=none")));
        }

        [DataRow("v=DMARC1", "p")]
        [DataRow("v=DMARC1; p=invalid", "p")]
        [DataRow("v=DMARC1; p=reject; sp=invalid", "sp")]
        [DataRow("v=DMARC1; p=reject; np=invalid", "np")]
        [DataRow("v=DMARC1; p=invalid; rua=https://example.com/report", "p")]
        [DataRow("v=DMARC1; p=invalid; rua=mailto:invalid", "p")]
        [TestMethod]
        public void TryParse_NoValidPolicyWithoutReportUri_ReturnsFalseWithCriticalError(string recordRaw, string invalidTag)
        {
            var isParserSuccessful = DmarcRecordParser.TryParse(recordRaw, out var dmarcRecord, out var parsingResults);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Any(o => o.Field == invalidTag && o.Status == ParsingStatus.Critical));
        }

        [TestMethod]
        public void TryParse_ReportUriWithOtherScheme_IsIgnoredWithWarning()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject; rua=https://example.com/report, mailto:dmarc@example.com", out var parsingResults);

            // Every URI is allowed, mail receivers only have to support mailto (RFC 9989 section 4.7)
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual("rua", parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Warning, parsingResults[0].Status);

            Assert.IsNotNull(dmarcRecord.AggregateReportUri);
            Assert.AreEqual(1, dmarcRecord.AggregateReportUri.Length);
            Assert.AreEqual("dmarc@example.com", dmarcRecord.AggregateReportUri[0].EmailAddress);
        }

        [TestMethod]
        public void TryParse_InvalidReportUri_IsIgnoredWithError()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject; rua=dmarc@example.com", out var parsingResults);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
            Assert.IsNull(dmarcRecord.AggregateReportUri);
        }

        [TestMethod]
        public void TryParse_WhitespaceAroundEqualSign_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var dmarcRecord = Parse("v = DMARC1 ; p = reject ; rua = mailto:dmarc@example.com ; adkim = s", out var parsingResults);

            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecord.DkimAlignmentMode);
            Assert.IsNotNull(dmarcRecord.AggregateReportUri);
            Assert.AreEqual("dmarc@example.com", dmarcRecord.AggregateReportUri[0].EmailAddress);
        }

        [TestMethod]
        public void TryParse_PartWithoutEqualSign_ParsesFollowingTagsAndReturnsError()
        {
            var dmarcRecord = Parse("v=DMARC1; p=reject; garbage; ; adkim=s; rua=mailto:dmarc@example.com", out var parsingResults);

            // The tags after the invalid part are still part of the record
            Assert.AreEqual(DmarcPolicy.Reject, dmarcRecord.DomainPolicy);
            Assert.AreEqual(AlignmentMode.Strict, dmarcRecord.DkimAlignmentMode);
            Assert.IsNotNull(dmarcRecord.AggregateReportUri);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual("garbage", parsingResults[0].Field);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
        }

        [TestMethod]
        public void TryParse_DuplicateTag_ReturnsError()
        {
            Parse("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; p = none", out var parsingResults);

            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.AreEqual(1, parsingResults.Length);
            Assert.AreEqual(ParsingStatus.Error, parsingResults[0].Status);
            Assert.IsTrue(parsingResults[0].Message.Contains("Duplicate"));
        }

        [DataRow("p=none,reject")]
        [DataRow("p=None, Reject")]
        [TestMethod]
        public void TryParse_PolicyList_ReturnsFalse(string policy)
        {
            var isParserSuccessful = DmarcRecordParser.TryParse($"v=DMARC1; {policy}", out var dmarcRecord);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
        }

        [DataRow("v=DMARC1; p=reject")]
        [DataRow("v=DMARC1")]
        [DataRow("v=DMARC1;")]
        [DataRow("V=DMARC1; p=reject")]
        [DataRow("v = DMARC1 ; p=reject")]
        [DataRow(" v=DMARC1; p=reject")]
        [TestMethod]
        public void IsDmarcRecord_DmarcRecord_ReturnsTrue(string txtRecord)
        {
            Assert.IsTrue(DmarcRecordParser.IsDmarcRecord(txtRecord));
        }

        [DataRow(null)]
        [DataRow("")]
        [DataRow(" ")]
        [DataRow("v=dmarc1; p=reject")]
        [DataRow("v=DMARC10; p=reject")]
        [DataRow("v=DMARC2; p=reject")]
        [DataRow("p=reject; v=DMARC1")]
        [DataRow("v=spf1 -all")]
        [DataRow("google-site-verification=abc")]
        [TestMethod]
        public void IsDmarcRecord_OtherRecord_ReturnsFalse(string? txtRecord)
        {
            Assert.IsFalse(DmarcRecordParser.IsDmarcRecord(txtRecord));
        }

        [TestMethod]
        public void TryParse_VersionInLowerCase_ReturnsFalse()
        {
            // The value of the version tag is case sensitive, mail receivers ignore the record (RFC 9989 section 4.7)
            var isParserSuccessful = DmarcRecordParser.TryParse("v=dmarc1; p=reject", out var dmarcRecord, out var parsingResults);

            Assert.IsFalse(isParserSuccessful);
            Assert.IsNull(dmarcRecord);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

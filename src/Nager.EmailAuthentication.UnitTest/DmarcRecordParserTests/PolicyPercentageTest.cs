﻿namespace Nager.EmailAuthentication.UnitTest.DmarcRecordParserTests
{
    [TestClass]
    public sealed class PolicyPercentageTest
    {
        [TestMethod]
        public void TryParse_ValidDmarcString1_ReturnsTrueAndPopulatesDmarcRecord()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=reject; pct=60;", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("60", dmarcDataFragment.PolicyPercentage);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString1_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=reject; pct=;", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("", dmarcDataFragment.PolicyPercentage);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }

        [TestMethod]
        public void TryParse_InvalidDmarcString2_ReturnsTrueWithErrors()
        {
            var isSuccessful = DmarcRecordDataFragmentParser.TryParse("v=DMARC1; p=reject; pct=200;", out var dmarcDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dmarcDataFragment);
            Assert.AreEqual("reject", dmarcDataFragment.DomainPolicy);
            Assert.AreEqual("200", dmarcDataFragment.PolicyPercentage);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
            Assert.IsTrue(parsingResults.Length == 1);
        }
    }
}

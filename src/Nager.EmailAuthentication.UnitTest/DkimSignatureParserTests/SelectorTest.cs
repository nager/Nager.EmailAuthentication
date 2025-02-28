using Nager.EmailAuthentication.FragmentParsers;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class SelectorTest
    {
        [DataRow("selector1")]
        [DataRow("selector2")]
        [DataRow("google")]
        [DataTestMethod]
        public void TryParse_ValidSelector_ReturnsTrueAndPopulatesDataFragment(string selector)
        {
            var dkimSignature = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=from:to:reply-to:subject:date:cc:content-type; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [DataRow("verylongandinvalidselectorverylongandinvalidselectorverylongandinvalidselector")]
        [DataRow("-test")]
        [DataRow("-test-")]
        [DataRow("_test")]
        [DataRow("test_")]
        [DataTestMethod]
        public void TryParse_InvalidSelector_ReturnsTrueAndPopulatesDataFragment(string selector)
        {
            var dkimSignature = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=from:to:reply-to:subject:date:cc:content-type; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignature, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}

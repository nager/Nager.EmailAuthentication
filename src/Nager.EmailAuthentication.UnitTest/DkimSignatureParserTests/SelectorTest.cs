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
            var dkimSignature = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimHeaderDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [DataRow("verylongandinvalidselectorverylongandinvalidselectorverylongandinvalidselector")]
        [DataTestMethod]
        public void TryParse_InvalidSelector_ReturnsTrueAndPopulatesDataFragment(string selector)
        {
            var dkimSignature = $"v=1; a=rsa-sha256; d=domain.com; s={selector}; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParser.TryParse(dkimSignature, out var dkimHeaderDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimHeaderDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}

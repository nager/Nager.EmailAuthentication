using Nager.EmailAuthentication.FragmentParsers;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class HeaderTest
    {
        [TestMethod]
        public void TryParse_NoHeadersDefined_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; s=test; h=; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignatureRaw, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_OnlyOneHeaderIsDefined_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; s=test; h=test; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureDataFragmentParserV1.TryParse(dkimSignatureRaw, out var dkimSignatureDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignatureDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }
    }
}

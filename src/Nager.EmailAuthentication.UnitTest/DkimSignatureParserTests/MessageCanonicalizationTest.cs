using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class MessageCanonicalizationTest
    {
        [TestMethod]
        public void TryParse_NoMessageCanonicalization_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_SingleMessageCanonicalization1_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=relaxed; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationBody);
        }


        [TestMethod]
        public void TryParse_SingleMessageCanonicalization2_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=simple; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationBody);
        }

        [TestMethod]
        public void TryParse_DefaultMessageCanonicalization1_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=simple/simple; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationBody);
        }

        [TestMethod]
        public void TryParse_DefaultMessageCanonicalization2_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=simple/relaxed; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(CanonicalizationType.Simple, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationBody);
        }

        [TestMethod]
        public void TryParse_DefaultMessageCanonicalization3_ReturnsTrueAndPopulatesDkimSignature()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=relaxed/relaxed; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationBody);
        }

        [TestMethod]
        public void TryParse_InvalidMessageCanonicalization1_ReturnsFalse()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=test/test; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_InvalidMessageCanonicalization2_ReturnsFalse()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; d=domain.com; c=relaxed/simple/test; s=test; h=message-id:from; bh=testbodyhash=; b=signaturedata";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dkimSignature);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

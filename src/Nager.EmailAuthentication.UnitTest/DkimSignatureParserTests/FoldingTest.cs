using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureParserTests
{
    [TestClass]
    public sealed class FoldingTest
    {
        [TestMethod]
        public void TryParse_ValidSelector_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=\tdmarc.com; h=cc:content-transfer-encoding:content-type\t:content-type:date:date:from:from:in-reply-to:message-id\t:mime-version:reply-to:sender:subject:subject:to:to; s=selector1; t=\t1691032934; x=1691119334; bh=R3apwsNJ82/QU5M387ntjAXd9fEanDDMRVC\tWFXcJ4BU=; b=ERPju20CMzamO4CElotsxcged+Ospob+sROWU3fdwUXfA2edzbe\ttfb1QaOG5TM+qh4D5MwArT0VQTw7B/J2jvfTpgXTu/+8Lg8SOArRFyHTRQXfUDul\tY872sMKYLuO9n3I9ewthEZNen3m2YLVPQ5RyGkoBFSj1jh7m8crBgnFRBaztgOXc\tbNhI2OTdJckxlBoHQfggPEgwaoT1oJt0T8GQuUTqkEq/yD8K1CZ2hriBryRpw/tC\tBiDU/EK4fPEHKVzwRs+K3g6vPJ0tdz9zG5KyMnDtHmWfHymTXfJjnxhJ5DO5j/Nu\tng67Nt+cn+Jpmeko8eWd96TQzqokrW9PsoA==";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);

            Assert.AreEqual("1", dkimSignature.Version);
            Assert.AreEqual(SignatureAlgorithm.RsaSha256, dkimSignature.SignatureAlgorithm);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignature.MessageCanonicalizationBody);
            Assert.AreEqual("dmarc.com", dkimSignature.SigningDomainIdentifier);
            Assert.AreEqual("selector1", dkimSignature.Selector);
            //Assert.AreEqual(["cc"], dkimSignature.SignedHeaderFields);
            Assert.AreEqual(new DateTimeOffset(2023, 8, 3, 3, 22, 14, TimeSpan.Zero), dkimSignature.Timestamp);
            Assert.AreEqual(new DateTimeOffset(2023, 8, 4, 3, 22, 14, TimeSpan.Zero), dkimSignature.SignatureExpiration);
            

            //Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

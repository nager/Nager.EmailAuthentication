using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Dkim;

namespace Nager.EmailAuthentication.UnitTest.DkimSignatureTests.Parser
{
    [TestClass]
    public sealed class FoldingTest
    {
        /// <summary>
        /// DKIM signature folding refers to breaking long header field lines into multiple lines for better readability
        /// and compliance with email standards. It uses whitespace and line breaks while ensuring the signature remains valid.
        /// </summary>
        [TestMethod]
        public void TryParse_ValidSelector_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimSignatureRaw = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=\r\n\tdmarc.com; h=cc:content-transfer-encoding:content-type\r\n\t:content-type:date:date:from:from:in-reply-to:message-id\r\n\t:mime-version:reply-to:sender:subject:subject:to:to; s=selector1; t=\r\n\t1691032934; x=1691119334; bh=R3apwsNJ82/QU5M387ntjAXd9fEanDDMRVC\r\n\tWFXcJ4BU=; b=ERPju20CMzamO4CElotsxcged+Ospob+sROWU3fdwUXfA2edzbe\r\n\ttfb1QaOG5TM+qh4D5MwArT0VQTw7B/J2jvfTpgXTu/+8Lg8SOArRFyHTRQXfUDul\r\n\tY872sMKYLuO9n3I9ewthEZNen3m2YLVPQ5RyGkoBFSj1jh7m8crBgnFRBaztgOXc\r\n\tbNhI2OTdJckxlBoHQfggPEgwaoT1oJt0T8GQuUTqkEq/yD8K1CZ2hriBryRpw/tC\r\n\tBiDU/EK4fPEHKVzwRs+K3g6vPJ0tdz9zG5KyMnDtHmWfHymTXfJjnxhJ5DO5j/Nu\r\n\tng67Nt+cn+Jpmeko8eWd96TQzqokrW9PsoA==";

            var isSuccessful = DkimSignatureParser.TryParse(dkimSignatureRaw, out var dkimSignature, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimSignature);

            if (dkimSignature is not DkimSignatureV1 dkimSignatureV1)
            {
                Assert.Fail("Wrong DkimSignature class");
                return;
            }

            Assert.AreEqual("1", dkimSignatureV1.Version);
            Assert.AreEqual(SignatureAlgorithm.RsaSha256, dkimSignatureV1.SignatureAlgorithm);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignatureV1.MessageCanonicalizationHeader);
            Assert.AreEqual(CanonicalizationType.Relaxed, dkimSignatureV1.MessageCanonicalizationBody);
            Assert.AreEqual("dmarc.com", dkimSignatureV1.SigningDomainIdentifier);
            Assert.AreEqual("selector1", dkimSignatureV1.Selector);
            //Assert.AreEqual(["cc"], dkimSignature.SignedHeaderFields);
            Assert.AreEqual(new DateTimeOffset(2023, 8, 3, 3, 22, 14, TimeSpan.Zero), dkimSignatureV1.Timestamp);
            Assert.AreEqual(new DateTimeOffset(2023, 8, 4, 3, 22, 14, TimeSpan.Zero), dkimSignatureV1.SignatureExpiration);


            //Assert.IsNull(parsingResults, "ParsingResults is not null");
        }
    }
}

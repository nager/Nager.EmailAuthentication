using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication.UnitTest.DkimPublicKeyRecordTests.Parser
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_DkimPublicKeyRecordWithVersion_ReturnsTrueAndPopulatesData()
        {
            var dkimPublicKeyRecordRaw = "v=DKIM1;p=test;";

            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecord, "DkimPublicKeyRecord is null");

            if (dkimPublicKeyRecord is not DkimPublicKeyRecordV1 dkimPublicKeyRecordV1)
            {
                Assert.Fail("Wrong DkimPublicKeyRecordV1 class");
                return;
            }

            Assert.AreEqual("DKIM1", dkimPublicKeyRecordV1.Version);
            Assert.AreEqual("rsa", dkimPublicKeyRecordV1.KeyType);
            Assert.AreEqual("test", dkimPublicKeyRecordV1.PublicKeyData);
        }

        [TestMethod]
        public void TryParse_DkimPublicKeyRecordWithoutVersion_ReturnsTrueAndPopulatesData()
        {
            var dkimPublicKeyRecordRaw = "k=rsa; p=test";

            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);
            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecord, "DkimPublicKeyRecord is null");

            if (dkimPublicKeyRecord is not DkimPublicKeyRecordV1 dkimPublicKeyRecordV1)
            {
                Assert.Fail("Wrong DkimPublicKeyRecordV1 class");
                return;
            }

            Assert.AreEqual("DKIM1", dkimPublicKeyRecordV1.Version);
            Assert.AreEqual("rsa", dkimPublicKeyRecordV1.KeyType);
            Assert.AreEqual("test", dkimPublicKeyRecordV1.PublicKeyData);
        }

        [TestMethod]
        public void TryParse_WrongDkimPublicKeyRecord_ReturnsFalse()
        {
            var dkimPublicKeyRecordRaw = "v=DMARC1;p=reject;";

            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);
            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dkimPublicKeyRecord, "DkimPublicKeyRecord is not null");
        }
    }
}

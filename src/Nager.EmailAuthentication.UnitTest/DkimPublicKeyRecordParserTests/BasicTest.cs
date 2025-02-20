namespace Nager.EmailAuthentication.UnitTest.DkimPublicKeyRecordParserTests
{
    [TestClass]
    public sealed class BasicTest
    {
        [TestMethod]
        public void TryParse_ValidDkimPublicKeyRecord1_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimPublicKeyRecord = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuu8v3TAGlg2cKEVtHbqh5QfebUSdVp2qwH4NFaIG/rEsBshHI97fdP6TqiJCmpLhK8mHSQMit2HiHAEUApa0xAw7SI68XiBr6epKpTkHaUx27C/kjyuxYmGFOJy6mrDzeC2E5+Lp1u9QifjuBtUk78ORSA+EXeEMxssHy51NdHT0BlZGk1M+wXTxniQ2d198gDVjjqRGM433Q0AP6uSJac9LQj80tHkWrnr/bjct7EOdtF+6mDl4qjAaJTruk03Xt3Alaj+DIOPmnwP1mbPLQmK4blnzM7jwQc2kZz9gSJocc0nhs8KfuR6Xj23iSOJV+WEt6WoLoJzSl8/Dx5CKJwIDAQAB";

            var isSuccessful = DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecord, out var dkimPublicKeyRecordDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecordDataFragment);
            Assert.IsNull(parsingResults, "ParsingResults is not null");
        }

        [TestMethod]
        public void TryParse_InvalidDkimPublicKeyRecord2_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimPublicKeyRecord = "v=DKIM1; k=rsa; p=";

            var isSuccessful = DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecord, out var dkimPublicKeyRecordDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecordDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_InvalidDkimPublicKeyRecord3_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimPublicKeyRecord = "v=DKIM1; k=rsa; p=1";

            var isSuccessful = DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecord, out var dkimPublicKeyRecordDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecordDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_WrongDkimPublicKeyRecord1_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimPublicKeyRecordRaw = "v=DMARC1;p=reject;";

            var isSuccessful = DkimPublicKeyRecordDataFragmentParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecordDataFragment, out var parsingResults);

            Assert.IsTrue(isSuccessful);
            Assert.IsNotNull(dkimPublicKeyRecordDataFragment);
            Assert.IsNotNull(parsingResults, "ParsingResults is null");
        }

        [TestMethod]
        public void TryParse_WrongDkimPublicKeyRecord2_ReturnsTrueAndPopulatesDataFragment()
        {
            var dkimPublicKeyRecordRaw = "v=DMARC1;p=reject;";

            var isSuccessful = DkimPublicKeyRecordParser.TryParse(dkimPublicKeyRecordRaw, out var dkimPublicKeyRecord);
            Assert.IsFalse(isSuccessful);
            Assert.IsNull(dkimPublicKeyRecord, "DkimPublicKeyRecord is not null");
        }
    }
}

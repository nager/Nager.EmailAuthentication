using Nager.EmailAuthentication.KeyValueParser;

namespace Nager.EmailAuthentication.UnitTest
{
    [TestClass]
    public sealed class KeyValueParserTest
    {
        private static IEnumerable<IKeyValueParser> GetParsers()
        {
            yield return new StringSplitKeyValueParser(delimiter: ';', keyValueSeparator: '=');
            yield return new MemoryEfficientKeyValueParser(delimiter: ';', keyValueSeparator: '=');
        }

        [TestMethod]
        public void Parse_ValidData1_ReturnsParseResult()
        {
            foreach (var parser in GetParsers())
            {
                var result = parser.Parse("v=DMARC1; p=reject;");

                Assert.IsNotNull(result);

                var firstKeyValue = result.KeyValues.Single(o => o.Index == 0);
                Assert.AreEqual("v", firstKeyValue.Key);
                Assert.AreEqual("DMARC1", firstKeyValue.Value);

                var secondKeyValue = result.KeyValues.Single(o => o.Index == 1);
                Assert.AreEqual("p", secondKeyValue.Key);
                Assert.AreEqual("reject", secondKeyValue.Value);
            }
        }

        [TestMethod]
        public void Parse_ValidData2_ReturnsParseResult()
        {
            foreach (var parser in GetParsers())
            {
                var result = parser.Parse("v=DMARC1; p=reject");

                Assert.IsNotNull(result);

                var firstKeyValue = result.KeyValues.Single(o => o.Index == 0);
                Assert.AreEqual("v", firstKeyValue.Key);
                Assert.AreEqual("DMARC1", firstKeyValue.Value);

                var secondKeyValue = result.KeyValues.Single(o => o.Index == 1);
                Assert.AreEqual("p", secondKeyValue.Key);
                Assert.AreEqual("reject", secondKeyValue.Value);
            }
        }
    }
}

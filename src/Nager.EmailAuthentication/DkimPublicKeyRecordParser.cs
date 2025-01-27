using Nager.EmailAuthentication.Handlers;
using Nager.EmailAuthentication.Models;

namespace Nager.EmailAuthentication
{
    /// <summary>
    /// Dkim Public Key Record Parser
    /// </summary>
    public static class DkimPublicKeyRecordParser
    {
        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string dkimPublicKeyRecord,
            out DkimPublicKeyRecordDataFragment? dkimPublicKeyRecordDataFragment)
        {
            return TryParse(dkimPublicKeyRecord, out dkimPublicKeyRecordDataFragment, out _);
        }

        /// <summary>
        /// TryParse
        /// </summary>
        /// <param name="dkimPublicKeyRecord"></param>
        /// <param name="dkimPublicKeyRecordDataFragment"></param>
        /// <param name="parsingResults"></param>
        /// <returns></returns>
        public static bool TryParse(
            string dkimPublicKeyRecord,
            out DkimPublicKeyRecordDataFragment? dkimPublicKeyRecordDataFragment,
            out ParsingResult[]? parsingResults)
        {
            var handlers = new Dictionary<string, MappingHandler<DkimPublicKeyRecordDataFragment>>
            {
                {
                    "v", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Version = value,
                    }
                },
                {
                    "p", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.PublicKeyData = value,
                    }
                },
                {
                    "n", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Notes = value
                    }
                },
                {
                    "k", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.KeyType = value
                    }
                },
                {
                    "g", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Granularity = value
                    }
                },
                {
                    "t", new MappingHandler<DkimPublicKeyRecordDataFragment>
                    {
                        Map = (dataFragment, value) => dataFragment.Flags = value
                    }
                },
            };

            var parserBase = new KeyValueParserBase<DkimPublicKeyRecordDataFragment>(handlers);
            return parserBase.TryParse(dkimPublicKeyRecord, out dkimPublicKeyRecordDataFragment, out parsingResults);
        }
    }
}

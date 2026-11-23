using Nager.EmailAuthentication.Models;
using Nager.EmailAuthentication.Models.Spf;
using Nager.EmailAuthentication.Models.Spf.Mechanisms;
using Nager.EmailAuthentication.Models.Spf.Modifiers;
using System.Diagnostics.CodeAnalysis;

namespace Nager.EmailAuthentication.FragmentParsers
{
    /// <summary>
    /// Spf Record Data Fragment Parser
    /// </summary>
    public static class SpfRecordDataFragmentParserV1
    {
        /// <summary>
        /// Try Parse
        /// </summary>
        /// <param name="spfString"></param>
        /// <param name="spfDataFragment"></param>
        /// <returns></returns>
        public static bool TryParse(
            string? spfString,
            [NotNullWhen(true)] out SpfRecordDataFragmentV1? spfDataFragment)
        {
            return TryParse(spfString, out spfDataFragment, out _);
        }

        /// <summary>
        /// Attempts to parse a raw SPF string into a <see cref="SpfRecordDataFragmentV1"/> object while also
        /// returning the terms that could not be parsed.
        /// </summary>
        /// <param name="spfString">The raw SPF string to parse.</param>
        /// <param name="spfDataFragment">The parsed SPF record, if successful.</param>
        /// <param name="parsingResults">
        /// A list of the terms that are neither a mechanism nor a known modifier, if any. An unknown mechanism is
        /// a syntax error for a mail receiver (RFC 7208 section 4.6), an unknown modifier is ignored (RFC 7208 section 6).
        /// </param>
        /// <returns><see langword="true"/> if parsing is successful; otherwise <see langword="false"/>.</returns>
        public static bool TryParse(
            string? spfString,
            [NotNullWhen(true)] out SpfRecordDataFragmentV1? spfDataFragment,
            out ParsingResult[]? parsingResults)
        {
            var spfVersion = "v=spf1";
            parsingResults = null;

            if (string.IsNullOrWhiteSpace(spfString))
            {
                spfDataFragment = null;
                return false;
            }

            // The version is followed by a space or the end of the record (RFC 7208 section 4.5)
            if (!spfString.StartsWith(spfVersion, StringComparison.OrdinalIgnoreCase) ||
                (spfString.Length > spfVersion.Length && spfString[spfVersion.Length] != ' '))
            {
                spfDataFragment = null;
                return false;
            }

            var tempParsingResults = new List<ParsingResult>();
            var spfTerms = new List<SpfTerm>();
            var mechanismTypes = new Dictionary<string, Type>
            {
                { AllMechanism.MechanismKey,      typeof(AllMechanism) },
                { Ip4Mechanism.MechanismKey,      typeof(Ip4Mechanism) },
                { Ip6Mechanism.MechanismKey,      typeof(Ip6Mechanism) },
                { IncludeMechanism.MechanismKey,  typeof(IncludeMechanism) },
                { AMechanism.MechanismKey,        typeof(AMechanism) },
                { MxMechanism.MechanismKey,       typeof(MxMechanism) },
                { ExistsMechanism.MechanismKey,   typeof(ExistsMechanism) },
                { PtrMechanism.MechanismKey,      typeof(PtrMechanism) },
            };

            var modifierTypes = new Dictionary<string, Type>
            {
                { RedirectModifier.ModifierKey,   typeof(RedirectModifier) },
                { ExpModifier.ModifierKey,        typeof(ExpModifier) }
            };

            var spfTermDelimiter = ' ';
            var allowedQualifiers = new char[] { '+', '?', '~', '-' };
            var inputSpan = spfString.AsSpan()[spfVersion.Length..];
            var nextIndexOfDelimiter = 0;
            var termIndex = 0;

            while (nextIndexOfDelimiter != -1)
            {
                termIndex++;

                nextIndexOfDelimiter = inputSpan.IndexOf(spfTermDelimiter);

                if (nextIndexOfDelimiter == 0)
                {
                    inputSpan = inputSpan[1..];
                    continue;
                }

                ReadOnlySpan<char> value;
                if (nextIndexOfDelimiter == -1)
                {
                    value = inputSpan.Trim();
                }
                else
                {
                    value = inputSpan[..nextIndexOfDelimiter].Trim();
                }

                if (value.Length == 0)
                {
                    if (nextIndexOfDelimiter != -1)
                    {
                        inputSpan = inputSpan[nextIndexOfDelimiter..];
                    }

                    continue;
                }

                var qualifier = '+';
                var indexOfQualifier = Array.IndexOf(allowedQualifiers, value[0]);
                if (indexOfQualifier != -1)
                {
                    qualifier = allowedQualifiers[indexOfQualifier];
                    value = value[1..];
                }

                // The name of a term ends with its data: "include:example.com", "a/24", "redirect=example.com"
                var rawTerm = value.ToString();
                var indexOfNameEnd = value.IndexOfAny(':', '/', '=');
                var termName = indexOfNameEnd == -1 ? value : value[..indexOfNameEnd];
                var isModifier = indexOfNameEnd != -1 && value[indexOfNameEnd] == '=';

                var match = false;

                foreach (var mechanismType in mechanismTypes)
                {
                    if (isModifier || !termName.Equals(mechanismType.Key, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (Activator.CreateInstance(mechanismType.Value) is not SpfTerm term)
                    {
                        continue;
                    }

                    term.Index = termIndex;

                    if (term is MechanismBase spfMechanism)
                    {
                        spfMechanism.SetQualifier(qualifier);

                        value = value[mechanismType.Key.Length..];
                        if (value.Length > 0)
                        {
                            spfMechanism.GetDataPart(value);
                        }

                        spfTerms.Add(spfMechanism);
                        match = true;
                        break;
                    }
                }

                if (!match)
                {
                    foreach (var modifierType in modifierTypes)
                    {
                        if (!isModifier || !termName.Equals(modifierType.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (Activator.CreateInstance(modifierType.Value) is not SpfTerm term)
                        {
                            continue;
                        }

                        term.Index = termIndex;

                        if (term is ModifierBase spfModifier)
                        {
                            value = value[modifierType.Key.Length..];
                            if (value.Length > 0)
                            {
                                spfModifier.GetDataPart(value);
                            }

                            spfTerms.Add(spfModifier);
                            match = true;
                            break;
                        }
                    }
                }

                if (!match)
                {
                    // The name of a modifier starts with a letter (RFC 7208 section 12)
                    var isUnknownModifier = isModifier && termName.Length > 0 && char.IsAsciiLetter(termName[0]);

                    tempParsingResults.Add(isUnknownModifier
                        ? new ParsingResult
                        {
                            Status = ParsingStatus.Info,
                            Field = termName.ToString(),
                            Message = $"Unknown modifier, mail receivers ignore it: {rawTerm}"
                        }
                        : new ParsingResult
                        {
                            Status = ParsingStatus.Error,
                            Field = termName.ToString(),
                            Message = $"Unknown term, the record has a syntax error: {rawTerm}"
                        });
                }

                inputSpan = inputSpan[(nextIndexOfDelimiter + 1)..];
            }

            parsingResults = tempParsingResults.Count == 0 ? null : [.. tempParsingResults];

            spfDataFragment = new SpfRecordDataFragmentV1
            {
                Version = "1",
                SpfTerms = [.. spfTerms]
            };

            return true;
        }
    }
}

using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;

namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Represents the details of a DMARC email address, including validation status and maximum size.
    /// </summary>
    public class DmarcEmailDetail
    {
        /// <summary>
        /// Gets or sets the email address.
        /// </summary>
        public required string EmailAddress { get; set; }

        /// <summary>
        /// Indicates whether the email address is valid.
        /// </summary>
        public bool IsValidEmailAddress { get; set; }

        /// <summary>
        /// Gets or sets the maximum size allowed for the email, in bytes.
        /// Nullable if no maximum size is specified.
        /// </summary>
        public int? MaximumSize { get; set; }

        /// <summary>
        /// Try parse Uri Email Address
        /// </summary>
        /// <param name="uriEmail"></param>
        /// <param name="dmarcEmailDetail"></param>
        /// <returns></returns>
        public static bool TryParse(
            string uriEmail,
            [NotNullWhen(true)] out DmarcEmailDetail? dmarcEmailDetail)
        {
            if (string.IsNullOrEmpty(uriEmail))
            {
                dmarcEmailDetail = null;
                return false;
            }

            const string mailtoPrefix = "mailto:";

            if (!uriEmail.StartsWith(mailtoPrefix, StringComparison.OrdinalIgnoreCase))
            {
                dmarcEmailDetail = null;
                return false;
            }

            var emailAddress = uriEmail.Substring(mailtoPrefix.Length);

            var exclamationMarkIndex = emailAddress.IndexOf('!');
            if (exclamationMarkIndex == -1)
            {
                dmarcEmailDetail = new DmarcEmailDetail
                {
                    EmailAddress = emailAddress,
                    IsValidEmailAddress = CheckIsValidEmailAddress(emailAddress)
                };

                return true;
            }

            var dataStartIndex = exclamationMarkIndex + 1;
            var dataLength = emailAddress.Length - dataStartIndex;

            if (int.TryParse(emailAddress.AsSpan(dataStartIndex, dataLength - 1), out var maximumSize))
            {
                var multiplier = 0;
                var maximumSizeUnit = emailAddress.AsSpan(dataStartIndex + dataLength - 1);
                if (maximumSizeUnit.SequenceEqual(['k']))
                {
                    multiplier = 1;
                }
                if (maximumSizeUnit.SequenceEqual(['m']))
                {
                    multiplier = 1024;
                }

                var cleanEmailAddress = emailAddress[..exclamationMarkIndex];

                dmarcEmailDetail = new DmarcEmailDetail
                {
                    EmailAddress = cleanEmailAddress,
                    IsValidEmailAddress = CheckIsValidEmailAddress(cleanEmailAddress),
                    MaximumSize = maximumSize * multiplier
                };

                return true;
            }

            dmarcEmailDetail = null;
            return false;
        }

        private static bool CheckIsValidEmailAddress(string emailAddress)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
            {
                return false;
            }

            return MailAddress.TryCreate(emailAddress, out _);
        }
    }
}

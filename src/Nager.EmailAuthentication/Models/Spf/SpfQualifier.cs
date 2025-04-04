namespace Nager.EmailAuthentication.Models.Spf
{
    /// <summary>
    /// Represents the possible qualifiers for an SPF (Sender Policy Framework) mechanism.
    /// </summary>
    public enum SpfQualifier
    {
        /// <summary>
        /// The qualifier is unknown or not set.
        /// </summary>
        Unknown,

        /// <summary>
        /// The SPF check passed, meaning the sender is authorized.
        /// </summary>
        Pass,

        /// <summary>
        /// The SPF check resulted in a soft fail, indicating that the sender is not authorized but mail may still be accepted.
        /// </summary>
        SoftFail,

        /// <summary>
        /// The SPF check failed, meaning the sender is explicitly not authorized.
        /// </summary>
        Fail,

        /// <summary>
        /// The SPF check returned a neutral result, meaning no strong policy is specified.
        /// </summary>
        Neutral
    }
}

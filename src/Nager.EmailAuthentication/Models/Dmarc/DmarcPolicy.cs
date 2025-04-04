namespace Nager.EmailAuthentication.Models.Dmarc
{
    /// <summary>
    /// Defines the DMARC policy actions that can be applied to emails failing authentication checks.
    /// </summary>
    public enum DmarcPolicy
    {
        /// <summary>
        /// No specific action is taken on emails that fail DMARC checks.  
        /// The email is delivered as usual.
        /// </summary>
        None,

        /// <summary>
        /// Emails that fail DMARC checks should be treated as suspicious and placed in quarantine.  
        /// The receiving mail server may deliver them to the spam folder.
        /// </summary>
        Quarantine,

        /// <summary>
        /// Emails that fail DMARC checks should be rejected outright.  
        /// The receiving mail server will refuse delivery.
        /// </summary>
        Reject
    }
}

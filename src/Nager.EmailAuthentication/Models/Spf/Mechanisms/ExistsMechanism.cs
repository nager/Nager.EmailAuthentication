namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    /// <summary>
    /// Represents the "exists" mechanism in an SPF record, which authorizes the sender if a specific DNS record exists.
    /// </summary>
    public class ExistsMechanism : MechanismBase
    {
        /// <summary>
        /// The key representing the "exists" mechanism in an SPF record.
        /// </summary>
        public const string MechanismKey = "exists";

        /// <summary>
        /// Initializes a new instance of the <see cref="ExistsMechanism"/> class.
        /// </summary>
        public ExistsMechanism() : base(MechanismType.Exists)
        {

        }
    }
}

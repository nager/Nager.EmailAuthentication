namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class AMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "a";

        public AMechanism() : base(MechanismType.A)
        {

        }
    }
}

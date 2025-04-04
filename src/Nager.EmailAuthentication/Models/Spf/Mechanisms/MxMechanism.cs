namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class MxMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "mx";

        public MxMechanism() : base(MechanismType.Mx)
        {

        }
    }
}

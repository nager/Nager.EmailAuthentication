namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class PtrMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "ptr";

        public PtrMechanism() : base(MechanismType.Ptr)
        {

        }
    }
}

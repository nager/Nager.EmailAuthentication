namespace Nager.EmailAuthentication.Models.Spf.Mechanisms
{
    public class ExistsMechanism : SpfMechanismBase
    {
        public const string MechanismKey = "exists";

        public ExistsMechanism() : base(MechanismType.Exists)
        {

        }
    }
}

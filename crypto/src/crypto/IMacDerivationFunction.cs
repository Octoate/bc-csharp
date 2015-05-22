/**
 * base interface for general purpose Mac based byte derivation functions.
 */
namespace Org.BouncyCastle.Crypto
{
    public interface MacDerivationFunction : IDerivationFunction
    {
        /**
         * return the MAC used as the basis for the function
         */
        public IMac getMac();
    }
}
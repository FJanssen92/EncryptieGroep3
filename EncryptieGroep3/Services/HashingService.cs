using System.Security.Cryptography;
using System.Text;

namespace EncryptieGroep3.Services
{
    public enum HashAlgorithmType { MD5, SHA1, SHA256, SHA384, SHA512 }

    public class HashingService
    {
        public string ComputeHash(string input, HashAlgorithmType type)
        {
            using var algorithm = CreateHashAlgorithm(type);
            byte[] hashBytes = algorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        public string ComputeFileHash(Stream fileStream, HashAlgorithmType type)
        {
            using var algorithm = CreateHashAlgorithm(type);
            byte[] hashBytes = algorithm.ComputeHash(fileStream);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        public bool VerifyHash(string input, string expectedHash, HashAlgorithmType type)
        {
            string computed = ComputeHash(input, type);
            return string.Equals(computed, expectedHash.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        public string ComputeHmac(string input, string key, HashAlgorithmType type)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            using var hmac = CreateHmacAlgorithm(type, keyBytes);
            byte[] hashBytes = hmac.ComputeHash(inputBytes);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        public bool VerifyHmac(string input, string key, string expectedHmac, HashAlgorithmType type)
        {
            string computed = ComputeHmac(input, key, type);
            return string.Equals(computed, expectedHmac.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        private HashAlgorithm CreateHashAlgorithm(HashAlgorithmType type)
        {
            return type switch
            {
                HashAlgorithmType.MD5 => MD5.Create(),
                HashAlgorithmType.SHA1 => SHA1.Create(),
                HashAlgorithmType.SHA256 => SHA256.Create(),
                HashAlgorithmType.SHA384 => SHA384.Create(),
                HashAlgorithmType.SHA512 => SHA512.Create(),
                _ => throw new ArgumentOutOfRangeException(nameof(type), "Unsupported hash algorithm.")
            };
        }

        private HMAC CreateHmacAlgorithm(HashAlgorithmType type, byte[] key)
        {
            return type switch
            {
                HashAlgorithmType.MD5 => new HMACMD5(key),
                HashAlgorithmType.SHA1 => new HMACSHA1(key),
                HashAlgorithmType.SHA256 => new HMACSHA256(key),
                HashAlgorithmType.SHA384 => new HMACSHA384(key),
                HashAlgorithmType.SHA512 => new HMACSHA512(key),
                _ => throw new ArgumentOutOfRangeException(nameof(type), "Unsupported HMAC algorithm.")
            };
        }
    }
}

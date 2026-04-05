using System.Security.Cryptography;

namespace EncryptieGroep3.Services
{
    public class KeyGenerationService
    {
        public (byte[] Key, byte[] IV) GenerateAesKeyPair(int keySize)
        {
            if (keySize != 128 && keySize != 192 && keySize != 256)
            {
                throw new ArgumentException("AES key size must be 128, 192, or 256 bits.");
            }

            using Aes aes = Aes.Create();
            aes.KeySize = keySize;
            aes.GenerateKey();
            aes.GenerateIV();

            return (aes.Key, aes.IV);
        }

        public (string PublicKeyPem, string PrivateKeyPem) GenerateRsaKeyPair(int keySize)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
            {
                throw new ArgumentException("RSA key size must be 1024, 2048, or 4096 bits.");
            }

            using RSA rsa = RSA.Create(keySize);
            string publicKey = rsa.ExportRSAPublicKeyPem();
            string privateKey = rsa.ExportRSAPrivateKeyPem();

            return (publicKey, privateKey);
        }

        public string ExportKeyToBase64(byte[] key)
        {
            return Convert.ToBase64String(key);
        }

        public string ExportKeyToHex(byte[] key)
        {
            return Convert.ToHexString(key);
        }
    }
}

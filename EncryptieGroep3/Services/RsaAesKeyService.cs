using System.Security.Cryptography;

namespace EncryptieGroep3.Services
{
    public class RsaAesKeyService
    {
        // Wraps an AES key with RSA-OAEP (SHA-256) using the recipient's public key.
        // This is how user A safely sends the AES key to user B.
        public string EncryptAesKeyWithRsa(string aesKeyBase64, string publicKeyXml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(publicKeyXml);
            byte[] aesKeyBytes = Convert.FromBase64String(aesKeyBase64);
            byte[] encrypted = rsa.Encrypt(aesKeyBytes, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(encrypted);
        }

        // User B unwraps the AES key using a RSA private key, giving him the original AES key.
        public string DecryptAesKeyWithRsa(string encryptedAesKeyBase64, string privateKeyXml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(privateKeyXml);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedAesKeyBase64);
            byte[] decrypted = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(decrypted);
        }

        // Bonus: Digital signatures
        public byte[] SignData(byte[] data, RSA privateKey)
        {
            return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public bool VerifySignature(byte[] data, byte[] signature, RSA publicKey)
        {
            return publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}

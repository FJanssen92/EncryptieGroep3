using EncryptieGroep3.Models;
using System.Security.Cryptography;
using System.Text;

namespace EncryptieGroep3.Services
{
    public class AesEncryptionService
    {
        public EncryptionResult Encrypt(string plainText, byte[] key, byte[] iv, CipherMode mode, PaddingMode padding)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = mode;
                aes.Padding = padding;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                    return new EncryptionResult
                    {
                        CipherBytes = cipherBytes,
                        CipherTextBase64 = Convert.ToBase64String(cipherBytes),
                        Success = true
                    };
                }
            }
        }

        public string Decrypt(byte[] cipherBytes, byte[] key, byte[] iv, CipherMode mode, PaddingMode padding)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = mode;
                aes.Padding = padding;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }
        }
    }
}

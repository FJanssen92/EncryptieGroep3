namespace EncryptieGroep3.Models
{
    public class RsaViewModel
    {
        public string? AesKey { get; set; }
        public string? PublicKey { get; set; }
        public string? PrivateKey { get; set; }
        public string? EncryptedAesKey { get; set; }
        public string? DecryptedAesKey { get; set; }

        // Sign & Verify
        public string? DataToSign { get; set; }
        public string? SignPrivateKey { get; set; }
        public string? Signature { get; set; }
        public string? VerifyData { get; set; }
        public string? VerifyPublicKey { get; set; }
        public bool? SignatureValid { get; set; }
    }
}

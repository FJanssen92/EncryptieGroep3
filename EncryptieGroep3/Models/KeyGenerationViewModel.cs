namespace EncryptieGroep3.Models
{
    public class KeyGenerationViewModel
    {
        public string KeyType { get; set; } = "AES";

        public int AesKeySize { get; set; } = 256;
        public int RsaKeySize { get; set; } = 2048;

        public string SelectedAesFormat { get; set; } = "Base64";

        public string? AesKeyBase64 { get; set; }
        public string? AesKeyHex { get; set; }
        public string? AesIvBase64 { get; set; }
        public string? AesIvHex { get; set; }

        public string? RsaPublicKeyXml { get; set; }
        public string? RsaPrivateKeyXml { get; set; }
    }
}

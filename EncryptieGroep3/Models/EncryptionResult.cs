namespace EncryptieGroep3.Models
{
    public class EncryptionResult
    {
        public byte[]? CipherBytes { get; set; }
        public string? CipherTextBase64 { get; set; }
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
    }
}

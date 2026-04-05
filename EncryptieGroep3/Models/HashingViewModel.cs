namespace EncryptieGroep3.Models
{
    public class HashingViewModel
    {
        // Hash generation
        public string? InputText { get; set; }
        public string SelectedAlgorithm { get; set; } = "SHA256";
        public string? HashResult { get; set; }

        // File hashing
        public string? FileHashResult { get; set; }
        public string SelectedFileAlgorithm { get; set; } = "SHA256";

        // Hash verification
        public string? VerifyInputText { get; set; }
        public string? ExpectedHash { get; set; }
        public string VerifyAlgorithm { get; set; } = "SHA256";
        public bool? HashValid { get; set; }

        // HMAC generation
        public string? HmacInputText { get; set; }
        public string? HmacKey { get; set; }
        public string HmacAlgorithm { get; set; } = "SHA256";
        public string? HmacResult { get; set; }

        // HMAC verification
        public string? HmacVerifyInput { get; set; }
        public string? HmacVerifyKey { get; set; }
        public string? ExpectedHmac { get; set; }
        public string HmacVerifyAlgorithm { get; set; } = "SHA256";
        public bool? HmacValid { get; set; }
    }
}

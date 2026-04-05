namespace EncryptieGroep3.Models
{
    public class AesEncryptionViewModel
    {
        public string? PlainText { get; set; }
        public string? CipherText { get; set; }

        public string? Key { get; set; }
        public string? IV { get; set; }

        public string SelectedMode { get; set; } = "CBC";
        public string SelectedPadding { get; set; } = "PKCS7";

        public string? Result { get; set; }
        public string? ErrorMessage { get; set; }
    }
}

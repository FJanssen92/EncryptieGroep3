using System.Security.Cryptography;
using System.Text;
using EncryptieGroep3.Models;
using EncryptieGroep3.Services;
using Microsoft.AspNetCore.Mvc;

namespace EncryptieGroep3.Controllers
{
    public class SecurityController : Controller
    {
        private readonly RsaAesKeyService _rsaService;
        private readonly AesEncryptionService _aesEncryptionService;

        public SecurityController(RsaAesKeyService rsaService, AesEncryptionService aesEncryptionService)
        {
            _rsaService = rsaService;
            _aesEncryptionService = aesEncryptionService;
        }

        public IActionResult Index()
        {
            return View();
        }

        [ActionName("Part 1")]
        public IActionResult Part1()
        {
            return View("Part1");
        }

        [ActionName("Part 2")]
        public IActionResult Part2()
        {
            return View("Part2", new AesEncryptionViewModel());
        }

        [ActionName("Part 3")]
        public IActionResult Part3()
        {
            return View("Part3", new RsaViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part3Encrypt(RsaViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.AesKey))
            {
                ModelState.AddModelError(nameof(model.AesKey), "Please enter an AES key.");
                return View("Part3", model);
            }
            if (string.IsNullOrWhiteSpace(model.PublicKey))
            {
                ModelState.AddModelError(nameof(model.PublicKey), "Please provide an RSA public key.");
                return View("Part3", model);
            }

            try
            {
                model.EncryptedAesKey = _rsaService.EncryptAesKeyWithRsa(model.AesKey, model.PublicKey);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Encryption failed: " + ex.Message);
            }

            return View("Part3", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part3Decrypt(RsaViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.EncryptedAesKey))
            {
                ModelState.AddModelError(nameof(model.EncryptedAesKey), "Please enter an encrypted AES key.");
                return View("Part3", model);
            }
            if (string.IsNullOrWhiteSpace(model.PrivateKey))
            {
                ModelState.AddModelError(nameof(model.PrivateKey), "Please provide an RSA private key.");
                return View("Part3", model);
            }

            try
            {
                model.DecryptedAesKey = _rsaService.DecryptAesKeyWithRsa(model.EncryptedAesKey, model.PrivateKey);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Decryption failed: " + ex.Message);
            }

            return View("Part3", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part3Sign(RsaViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.DataToSign))
            {
                ModelState.AddModelError(nameof(model.DataToSign), "Please enter data to sign.");
                return View("Part3", model);
            }
            if (string.IsNullOrWhiteSpace(model.SignPrivateKey))
            {
                ModelState.AddModelError(nameof(model.SignPrivateKey), "Please provide an RSA private key.");
                return View("Part3", model);
            }

            try
            {
                using var rsa = RSA.Create();
                rsa.FromXmlString(model.SignPrivateKey);
                byte[] signature = _rsaService.SignData(Encoding.UTF8.GetBytes(model.DataToSign), rsa);
                model.Signature = Convert.ToBase64String(signature);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Signing failed: " + ex.Message);
            }

            return View("Part3", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part3Verify(RsaViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.VerifyData))
            {
                ModelState.AddModelError(nameof(model.VerifyData), "Please enter data to verify.");
                return View("Part3", model);
            }
            if (string.IsNullOrWhiteSpace(model.Signature))
            {
                ModelState.AddModelError(nameof(model.Signature), "Please enter the signature.");
                return View("Part3", model);
            }
            if (string.IsNullOrWhiteSpace(model.VerifyPublicKey))
            {
                ModelState.AddModelError(nameof(model.VerifyPublicKey), "Please provide an RSA public key.");
                return View("Part3", model);
            }

            try
            {
                using var rsa = RSA.Create();
                rsa.FromXmlString(model.VerifyPublicKey);
                byte[] data = Encoding.UTF8.GetBytes(model.VerifyData);
                byte[] signature = Convert.FromBase64String(model.Signature);
                model.SignatureValid = _rsaService.VerifySignature(data, signature, rsa);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Verification failed: " + ex.Message);
            }

            return View("Part3", model);
        }

        [ActionName("Part 4")]
        public IActionResult Part4()
        {
            return View("Part4");
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part2Encrypt(AesEncryptionViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.PlainText))
            {
                ModelState.AddModelError(nameof(model.PlainText), "Geef plaintext in.");
                return View("Part2", model);
            }

            if (string.IsNullOrWhiteSpace(model.Key))
            {
                ModelState.AddModelError(nameof(model.Key), "Geef een AES key in (Base64).");
                return View("Part2", model);
            }

            if (string.IsNullOrWhiteSpace(model.IV))
            {
                ModelState.AddModelError(nameof(model.IV), "Geef een IV in (Base64).");
                return View("Part2", model);
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(model.Key);
                byte[] ivBytes = Convert.FromBase64String(model.IV);

                ValidateAesInput(keyBytes, ivBytes);

                CipherMode mode = Enum.Parse<CipherMode>(model.SelectedMode);
                PaddingMode padding = Enum.Parse<PaddingMode>(model.SelectedPadding);

                EncryptionResult result = _aesEncryptionService.Encrypt(
                    model.PlainText,
                    keyBytes,
                    ivBytes,
                    mode,
                    padding
                );

                model.Result = result.CipherTextBase64;
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Key of IV is geen geldige Base64.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Encryptie mislukt: " + ex.Message);
            }

            return View("Part2", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part2Decrypt(AesEncryptionViewModel model)
        {
            if (string.IsNullOrWhiteSpace(model.CipherText))
            {
                ModelState.AddModelError(nameof(model.CipherText), "Geef ciphertext in (Base64).");
                return View("Part2", model);
            }

            if (string.IsNullOrWhiteSpace(model.Key))
            {
                ModelState.AddModelError(nameof(model.Key), "Geef een AES key in (Base64).");
                return View("Part2", model);
            }

            if (string.IsNullOrWhiteSpace(model.IV))
            {
                ModelState.AddModelError(nameof(model.IV), "Geef een IV in (Base64).");
                return View("Part2", model);
            }

            try
            {
                byte[] cipherBytes = Convert.FromBase64String(model.CipherText);
                byte[] keyBytes = Convert.FromBase64String(model.Key);
                byte[] ivBytes = Convert.FromBase64String(model.IV);

                ValidateAesInput(keyBytes, ivBytes);

                CipherMode mode = Enum.Parse<CipherMode>(model.SelectedMode);
                PaddingMode padding = Enum.Parse<PaddingMode>(model.SelectedPadding);

                string plainText = _aesEncryptionService.Decrypt(
                    cipherBytes,
                    keyBytes,
                    ivBytes,
                    mode,
                    padding
                );

                model.Result = plainText;
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Input is geen geldige Base64.");
            }
            catch (CryptographicException)
            {
                ModelState.AddModelError(string.Empty, "Decryptie mislukt. Controleer key, IV en mode.");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Decryptie mislukt: " + ex.Message);
            }

            return View("Part2", model);
        }

        private void ValidateAesInput(byte[] keyBytes, byte[] ivBytes)
        {
            if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
            {
                throw new Exception("AES key moet 128, 192 of 256 bit zijn.");
            }

            if (ivBytes.Length != 16)
            {
                throw new Exception("IV moet 16 bytes zijn.");
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part2Clear()
        {
            return View("Part2", new AesEncryptionViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part2EncryptFile(IFormFile file, string key, string iv, string selectedMode, string selectedPadding)
        {
            if (file == null || file.Length == 0)
            {
                ModelState.AddModelError(string.Empty, "Selecteer een bestand voor encryptie.");
                return View("Part2", new AesEncryptionViewModel());
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(key);
                byte[] ivBytes = Convert.FromBase64String(iv);

                ValidateAesInput(keyBytes, ivBytes);

                CipherMode mode = Enum.Parse<CipherMode>(selectedMode);
                PaddingMode padding = Enum.Parse<PaddingMode>(selectedPadding);

                ValidateFileInput(file, padding);

                using var memoryStream = new MemoryStream();
                file.CopyTo(memoryStream);
                byte[] fileBytes = memoryStream.ToArray();

                byte[] encryptedBytes = _aesEncryptionService.EncryptFile(
                    fileBytes,
                    keyBytes,
                    ivBytes,
                    mode,
                    padding
                );

                string encryptedFileName = file.FileName + ".enc";

                return File(encryptedBytes, "application/octet-stream", encryptedFileName);
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Key of IV is geen geldige Base64.");
                return View("Part2", new AesEncryptionViewModel());
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "File encryptie mislukt: " + ex.Message);
                return View("Part2", new AesEncryptionViewModel());
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Part2DecryptFile(IFormFile file, string key, string iv, string selectedMode, string selectedPadding)
        {
            if (file == null || file.Length == 0)
            {
                ModelState.AddModelError(string.Empty, "Selecteer een encrypted bestand voor decryptie.");
                return View("Part2", new AesEncryptionViewModel());
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(key);
                byte[] ivBytes = Convert.FromBase64String(iv);

                ValidateAesInput(keyBytes, ivBytes);

                CipherMode mode = Enum.Parse<CipherMode>(selectedMode);
                PaddingMode padding = Enum.Parse<PaddingMode>(selectedPadding);

                ValidateFileInput(file, padding);

                using var memoryStream = new MemoryStream();
                file.CopyTo(memoryStream);
                byte[] encryptedBytes = memoryStream.ToArray();

                byte[] decryptedBytes = _aesEncryptionService.DecryptFile(
                    encryptedBytes,
                    keyBytes,
                    ivBytes,
                    mode,
                    padding
                );

                string decryptedFileName = file.FileName.EndsWith(".enc")
                    ? file.FileName[..^4]
                    : "decrypted_" + file.FileName;

                return File(decryptedBytes, "application/octet-stream", decryptedFileName);
            }
            catch (FormatException)
            {
                ModelState.AddModelError(string.Empty, "Key of IV is geen geldige Base64.");
                return View("Part2", new AesEncryptionViewModel());
            }
            catch (CryptographicException)
            {
                ModelState.AddModelError(string.Empty, "File decryptie mislukt. Controleer key, IV, mode en padding.");
                return View("Part2", new AesEncryptionViewModel());
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "File decryptie mislukt: " + ex.Message);
                return View("Part2", new AesEncryptionViewModel());
            }
        }
        private void ValidateFileInput(IFormFile file, PaddingMode padding)
        {
            if (file == null || file.Length == 0)
            {
                throw new Exception("Er is geen bestand geselecteerd.");
            }

            if (file.Length > 10 * 1024 * 1024)
            {
                throw new Exception("Bestand is te groot. Maximum 10MB.");
            }

            if (padding == PaddingMode.None && (file.Length % 16 != 0))
            {
                throw new Exception("Bij Padding=None moet bestandsgrootte een veelvoud van 16 bytes zijn.");
            }
        }
    }
}

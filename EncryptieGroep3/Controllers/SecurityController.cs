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

        public SecurityController(RsaAesKeyService rsaService)
        {
            _rsaService = rsaService;
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
            return View("Part2");
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
    }
}

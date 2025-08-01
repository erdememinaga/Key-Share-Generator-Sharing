using Microsoft.AspNetCore.Mvc;
using ShamirSecretSharing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

public class ShamirController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Split(string secretInput, int total, int threshold, string format = "text")
    {
        var sss = new ShamirSecretSharingService();
        List<string> serializedShares = new List<string>();

        if (format == "hex")
        {
            // Hex string -> byte[]
            var secretBytes = Enumerable.Range(0, secretInput.Length / 2)
                .Select(i => Convert.ToByte(secretInput.Substring(i * 2, 2), 16))
                .ToArray();
            var shares = sss.SplitSecret(secretBytes, total, threshold);
            serializedShares = shares.Select(s => s.ToString()).ToList();
        }
        else // text
        {
            var shares = sss.SplitSecret(secretInput, total, threshold);
            serializedShares = shares.Select(s => s.ToString()).ToList();
        }

        ViewBag.SecretInput = secretInput;
        ViewBag.Format = format;
        ViewBag.Total = total;
        ViewBag.Threshold = threshold;
        ViewBag.Shares = serializedShares.ToArray();

        return View("Index");
    }

    [HttpPost]
    public IActionResult Recover(string[] shares, string format = "text", int threshold = 3)
    {
        var sss = new ShamirSecretSharingService();
        // Replace .Select(Share.DeserializeFromString) with .Select(Share.Parse)
        var shareList = shares
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(Share.Parse)
            .ToList();

        if (shareList.Count < threshold)
        {
            ViewBag.Error = $"En az {threshold} share girmelisiniz!";
            return View("Index");
        }

        try
        {
            string result;
            if (format == "hex")
            {
                var secretBytes = sss.ReconstructSecret(shareList, threshold);
                result = BitConverter.ToString(secretBytes).Replace("-", "");
            }
            else // text
            {
                result = sss.ReconstructSecretString(shareList, threshold);
            }
            ViewBag.RecoveredSecret = result;
        }
        catch (ArgumentException ex)
        {
            ViewBag.Error = $"Birleştirme başarısız: {ex.Message}";
        }

        return View("Index");
    }
}

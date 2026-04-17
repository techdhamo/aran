using System;
using System.Collections.Generic;
using Microsoft.Maui.Controls;

namespace XamarinMAUIDemo
{
    public partial class RASPDemoPage : ContentPage
    {
        private bool isInitialized = false;
        private List<SecurityCheckResult> results = new List<SecurityCheckResult>();

        public RASPDemoPage()
        {
            InitializeComponent();
            InitializeRASP();
        }

        private void InitializeRASP()
        {
            try
            {
                // Initialize Xamarin/MAUI RASP bridge
                RASPNative.Initialize();
                isInitialized = true;
                UpdateStatus(true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to initialize RASP: {ex.Message}");
                isInitialized = false;
                UpdateStatus(false);
            }
        }

        private void UpdateStatus(bool initialized)
        {
            if (initialized)
            {
                StatusIcon.Text = "●";
                StatusIcon.TextColor = Colors.Green;
                StatusText.Text = "Initialized";
                StatusText.TextColor = Colors.Green;
            }
            else
            {
                StatusIcon.Text = "○";
                StatusIcon.TextColor = Colors.Red;
                StatusText.Text = "Not Initialized";
                StatusText.TextColor = Colors.Red;
            }
        }

        private void OnRunAllClicked(object sender, EventArgs e)
        {
            if (!isInitialized)
            {
                InitializeRASP();
            }

            results.Clear();
            UpdateResults();

            RunSecurityCheck("Integrity Check", RASPSelectors.IntegrityCheck);
            RunSecurityCheck("Debugger Check", RASPSelectors.DebugCheck);
            RunSecurityCheck("Root Check", RASPSelectors.RootCheck);
            RunSecurityCheck("Jailbreak Check", RASPSelectors.JailbreakCheck);
            RunSecurityCheck("Frida Check", RASPSelectors.FridaCheck);
            RunSecurityCheck("Emulator Check", RASPSelectors.EmulatorCheck);
        }

        private void RunSecurityCheck(string name, int selector)
        {
            int result = RASPNative.ExecuteAudit(selector);

            SecurityCheckResult checkResult = new SecurityCheckResult
            {
                Name = name,
                Result = result,
                Timestamp = DateTime.Now
            };

            results.Add(checkResult);
            UpdateResults();
        }

        private void UpdateResults()
        {
            if (results.Count == 0)
            {
                ResultsLabel.Text = "No security checks run yet";
                ResultsLabel.TextColor = Colors.Gray;
                return;
            }

            string resultsText = "";
            foreach (var result in results)
            {
                string icon = GetResultIcon(result.Result);
                resultsText += $"{icon} {result.Name}: 0x{result.Result.ToString("X")}\n";
            }

            ResultsLabel.Text = resultsText.Trim();
            ResultsLabel.TextColor = Colors.Black;
        }

        private string GetResultIcon(int result)
        {
            if (result == 0x7F3D) return "✓";
            if (result == 0x1A2B) return "⚠";
            return "✗";
        }
    }

    public class SecurityCheckResult
    {
        public string Name { get; set; }
        public int Result { get; set; }
        public DateTime Timestamp { get; set; }
    }
}

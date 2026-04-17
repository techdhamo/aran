using UnityEngine;
using UnityEngine.UI;
using System.Collections.Generic;

public class RASPDemo : MonoBehaviour
{
    public Button runAllButton;
    public Text statusText;
    public GameObject resultsContainer;
    public GameObject resultItemPrefab;
    
    private bool isInitialized = false;
    private List<SecurityCheckResult> results = new List<SecurityCheckResult>();
    
    void Start()
    {
        if (runAllButton != null)
        {
            runAllButton.onClick.AddListener(RunAllChecks);
        }
        
        InitializeRASP();
    }
    
    void InitializeRASP()
    {
        try
        {
            // Initialize Unity RASP bridge
            RASPNative.Initialize();
            isInitialized = true;
            UpdateStatus(true);
        }
        catch (System.Exception e)
        {
            Debug.LogError($"Failed to initialize RASP: {e.Message}");
            isInitialized = false;
            UpdateStatus(false);
        }
    }
    
    void UpdateStatus(bool initialized)
    {
        if (statusText != null)
        {
            statusText.text = initialized ? "● Initialized" : "○ Not Initialized";
            statusText.color = initialized ? Color.green : Color.red;
        }
    }
    
    public void RunAllChecks()
    {
        if (!isInitialized)
        {
            InitializeRASP();
        }
        
        results.Clear();
        ClearResults();
        
        RunSecurityCheck("Integrity Check", RASPSelectors.IntegrityCheck);
        RunSecurityCheck("Debugger Check", RASPSelectors.DebugCheck);
        RunSecurityCheck("Root Check", RASPSelectors.RootCheck);
        RunSecurityCheck("Jailbreak Check", RASPSelectors.JailbreakCheck);
        RunSecurityCheck("Frida Check", RASPSelectors.FridaCheck);
        RunSecurityCheck("Emulator Check", RASPSelectors.EmulatorCheck);
    }
    
    void RunSecurityCheck(string name, int selector)
    {
        int result = RASPNative.ExecuteAudit(selector);
        
        SecurityCheckResult checkResult = new SecurityCheckResult
        {
            name = name,
            result = result,
            timestamp = System.DateTime.Now
        };
        
        results.Add(checkResult);
        AddResultItem(checkResult);
    }
    
    void ClearResults()
    {
        if (resultsContainer != null)
        {
            foreach (Transform child in resultsContainer.transform)
            {
                Destroy(child.gameObject);
            }
        }
    }
    
    void AddResultItem(SecurityCheckResult result)
    {
        if (resultItemPrefab != null && resultsContainer != null)
        {
            GameObject item = Instantiate(resultItemPrefab, resultsContainer.transform);
            ResultItem resultItem = item.GetComponent<ResultItem>();
            
            if (resultItem != null)
            {
                resultItem.SetResult(result);
            }
        }
    }
    
    void OnDestroy()
    {
        if (isInitialized)
        {
            RASPNative.Shutdown();
        }
    }
}

public class SecurityCheckResult
{
    public string name;
    public int result;
    public System.DateTime timestamp;
}

public class ResultItem : MonoBehaviour
{
    public Text iconText;
    public Text nameText;
    public Text valueText;
    public Text timeText;
    
    public void SetResult(SecurityCheckResult result)
    {
        if (iconText != null)
        {
            iconText.text = GetResultIcon(result.result);
            iconText.color = GetResultColor(result.result);
        }
        
        if (nameText != null)
        {
            nameText.text = result.name;
        }
        
        if (valueText != null)
        {
            valueText.text = $"Result: 0x{result.result.ToString("X")}";
        }
        
        if (timeText != null)
        {
            timeText.text = result.timestamp.ToString("HH:mm:ss");
        }
    }
    
    string GetResultIcon(int result)
    {
        if (result == 0x7F3D) return "✓";
        if (result == 0x1A2B) return "⚠";
        return "✗";
    }
    
    Color GetResultColor(int result)
    {
        if (result == 0x7F3D) return Color.green;
        if (result == 0x1A2B) return new Color(1f, 0.6f, 0f); // Orange
        return Color.red;
    }
}

using Microsoft.AspNetCore.Mvc.RazorPages;
using SecuritySample.Models;
using SecuritySample.Services;

namespace SecuritySample.Pages;

public class IndexModel : PageModel
{
    public AnomalyDetectionService Detector { get; }

    public IndexModel(AnomalyDetectionService detector)
    {
        Detector = detector;
    }

    public IReadOnlyList<SecurityEvent> Events => Detector.GetEvents();
    public IReadOnlyDictionary<Severity, SlaRule> SlaRules => Detector.SlaRules;

    public int TotalEvents => Events.Count;
    public int AnomalyCount => Events.Count(e => e.IsAnomaly);
    public int AtRiskCount => Events.Count(e => Detector.GetSlaStatus(e) == SlaStatus.AtRisk);
    public int BreachedCount => Events.Count(e => Detector.GetSlaStatus(e) == SlaStatus.Breached);

    public void OnGet()
    {
    }
}

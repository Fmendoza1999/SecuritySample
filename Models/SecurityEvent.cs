namespace SecuritySample.Models;

public enum Severity { Critical, High, Medium, Low }
public enum EventStatus { Open, InProgress, Resolved }

public class SecurityEvent
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string SourceIp { get; set; } = "";
    public string EventType { get; set; } = "";       // e.g. "Failed Login", "Port Scan", "Traffic Spike"
    public string Description { get; set; } = "";
    public Severity Severity { get; set; }
    public EventStatus Status { get; set; } = EventStatus.Open;

    // --- SLA fields ---
    public DateTime? FirstResponseAt { get; set; }
    public DateTime? ResolvedAt { get; set; }

    // --- detection fields ---
    public bool IsAnomaly { get; set; }
    public double? AnomalyScore { get; set; } // z-score, how many std-devs above baseline
}

public class SlaRule
{
    public Severity Severity { get; set; }
    public int ResponseTimeMinutes { get; set; }
    public int ResolutionTimeMinutes { get; set; }

    public static readonly Dictionary<Severity, SlaRule> Rules = new()
    {
        [Severity.Critical] = new SlaRule { Severity = Severity.Critical, ResponseTimeMinutes = 15, ResolutionTimeMinutes = 240 },
        [Severity.High]     = new SlaRule { Severity = Severity.High,     ResponseTimeMinutes = 60, ResolutionTimeMinutes = 480 },
        [Severity.Medium]   = new SlaRule { Severity = Severity.Medium,   ResponseTimeMinutes = 240, ResolutionTimeMinutes = 1440 },
        [Severity.Low]      = new SlaRule { Severity = Severity.Low,      ResponseTimeMinutes = 1440, ResolutionTimeMinutes = 4320 },
    };
}

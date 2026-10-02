using SecuritySample.Models;

namespace SecuritySample.Services;

/// <summary>
/// Sample statistical anomaly detector. In the real project this would run
/// continuously over an incoming log/traffic stream (e.g. parsed Cisco syslog
/// or network flow data). Here it works over a fixed sample dataset to
/// demonstrate the core idea: flag events whose frequency is unusually high
/// compared to a rolling baseline, using a simple z-score.
/// </summary>
public class AnomalyDetectionService
{
    private readonly List<SecurityEvent> _events = new();
    private int _nextId = 1;

    public AnomalyDetectionService()
    {
        SeedSampleData();
        DetectAnomalies();
    }

    public IReadOnlyList<SecurityEvent> GetEvents() => _events.OrderByDescending(e => e.Timestamp).ToList();

    public IReadOnlyDictionary<Severity, SlaRule> SlaRules => SlaRule.Rules;

    public SlaStatus GetSlaStatus(SecurityEvent e)
    {
        var rule = SlaRule.Rules[e.Severity];
        var now = DateTime.UtcNow;

        var responseDeadline = e.Timestamp.AddMinutes(rule.ResponseTimeMinutes);
        var resolutionDeadline = e.Timestamp.AddMinutes(rule.ResolutionTimeMinutes);

        bool responseBreached = e.FirstResponseAt is null
            ? now > responseDeadline
            : e.FirstResponseAt > responseDeadline;

        bool resolutionBreached = e.Status != EventStatus.Resolved
            ? now > resolutionDeadline
            : e.ResolvedAt > resolutionDeadline;

        if (responseBreached || resolutionBreached) return SlaStatus.Breached;

        // "At risk" if open and within 20% of the resolution deadline
        if (e.Status != EventStatus.Resolved)
        {
            var totalWindow = (resolutionDeadline - e.Timestamp).TotalMinutes;
            var elapsed = (now - e.Timestamp).TotalMinutes;
            if (totalWindow > 0 && elapsed / totalWindow >= 0.8) return SlaStatus.AtRisk;
        }

        return SlaStatus.OnTrack;
    }

    /// <summary>
    /// Core detection logic: for each event type, compute a baseline (mean + std dev)
    /// of how many events of that type occur per hour across the sample window, then
    /// flag any hour whose count is more than 2 standard deviations above the mean.
    /// This is the same technique used to flag things like failed-login spikes or
    /// traffic bursts in a real log stream — just over a bigger window.
    /// </summary>
    private void DetectAnomalies()
    {
        var byType = _events.GroupBy(e => e.EventType);

        foreach (var group in byType)
        {
            var hourlyBuckets = group
                .GroupBy(e => new DateTime(e.Timestamp.Year, e.Timestamp.Month, e.Timestamp.Day, e.Timestamp.Hour, 0, 0))
                .Select(g => new { Hour = g.Key, Count = g.Count(), Events = g.ToList() })
                .ToList();

            if (hourlyBuckets.Count < 2) continue;

            double mean = hourlyBuckets.Average(b => b.Count);
            double variance = hourlyBuckets.Average(b => Math.Pow(b.Count - mean, 2));
            double stdDev = Math.Sqrt(variance);

            if (stdDev == 0) continue;

            foreach (var bucket in hourlyBuckets)
            {
                double zScore = (bucket.Count - mean) / stdDev;
                if (zScore > 2.0)
                {
                    foreach (var e in bucket.Events)
                    {
                        e.IsAnomaly = true;
                        e.AnomalyScore = Math.Round(zScore, 2);
                    }
                }
            }
        }
    }

    private void SeedSampleData()
    {
        var rnd = new Random(42);
        var now = DateTime.UtcNow;

        // Baseline: ordinary scattered events over the past 48 hours.
        var ordinaryTypes = new[] { "Failed Login", "Port Scan", "Malware Signature Hit", "Unusual Outbound Traffic" };
        var sourceIps = new[] { "10.0.0.14", "10.0.0.22", "192.168.1.8", "192.168.1.45", "172.16.0.9" };

        for (int h = 48; h >= 1; h--)
        {
            int countThisHour = rnd.Next(0, 3); // 0-2 ordinary events per hour
            for (int i = 0; i < countThisHour; i++)
            {
                AddEvent(
                    timestamp: now.AddHours(-h).AddMinutes(rnd.Next(0, 60)),
                    sourceIp: sourceIps[rnd.Next(sourceIps.Length)],
                    eventType: ordinaryTypes[rnd.Next(ordinaryTypes.Length)],
                    description: "Routine event, within normal volume",
                    severity: (Severity)rnd.Next(1, 4) // High/Medium/Low
                );
            }
        }

        // Inject a real spike: a brute-force-style burst of failed logins 3 hours ago.
        var spikeHour = now.AddHours(-3);
        for (int i = 0; i < 14; i++)
        {
            AddEvent(
                timestamp: spikeHour.AddMinutes(rnd.Next(0, 60)),
                sourceIp: "203.0.113.77", // external, unfamiliar IP
                eventType: "Failed Login",
                description: "Repeated failed login attempts against admin account",
                severity: Severity.Critical
            );
        }

        // Inject a second spike: a port scan burst 10 hours ago.
        var scanHour = now.AddHours(-10);
        for (int i = 0; i < 9; i++)
        {
            AddEvent(
                timestamp: scanHour.AddMinutes(rnd.Next(0, 60)),
                sourceIp: "198.51.100.23",
                eventType: "Port Scan",
                description: "Sequential port probing across internal subnet",
                severity: Severity.High
            );
        }

        // Mark some older events as already responded to / resolved, to show SLA states.
        foreach (var e in _events.Where(e => e.Timestamp < now.AddHours(-20)).Take(_events.Count / 2))
        {
            e.FirstResponseAt = e.Timestamp.AddMinutes(rnd.Next(5, 90));
            if (rnd.Next(0, 2) == 0)
            {
                e.Status = EventStatus.Resolved;
                e.ResolvedAt = e.FirstResponseAt.Value.AddMinutes(rnd.Next(30, 300));
            }
            else
            {
                e.Status = EventStatus.InProgress;
            }
        }
    }

    private void AddEvent(DateTime timestamp, string sourceIp, string eventType, string description, Severity severity)
    {
        _events.Add(new SecurityEvent
        {
            Id = _nextId++,
            Timestamp = timestamp,
            SourceIp = sourceIp,
            EventType = eventType,
            Description = description,
            Severity = severity
        });
    }
}

public enum SlaStatus { OnTrack, AtRisk, Breached }

namespace MergeGuard.Models
{
    public sealed class RiskReport
    {
        public int RiskScore { get; init; }                // 0-100
        public string RiskLevel { get; init; } = "Low";     // Low|Medium|High
        public List<string> Reasons { get; init; } = [];
        public List<string> RecommendedTests { get; init; } = [];
    }
}

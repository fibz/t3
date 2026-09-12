function severityCounts(cve = {}) {
  const source = cve.bySeverity || {};
  return { critical: Number(source.CRITICAL || 0), high: Number(source.HIGH || 0), medium: Number(source.MEDIUM || 0), low: Number(source.LOW || 0), unknown: Number(source.UNKNOWN || 0) };
}

function riskRating(counts) {
  if (counts.critical) return 'Critical';
  if (counts.high) return 'High';
  if (counts.medium) return 'Medium';
  if (counts.low) return 'Low';
  return 'Informational';
}

function createAssessmentSummary(scan) {
  const modules = (scan.results && scan.results.modules) || {};
  const cve = modules.cve || {};
  const counts = severityCounts(cve);
  return {
    risk: riskRating(counts), counts,
    totalVulnerabilities: Number(cve.totalVulnerabilities || 0),
    checksCompleted: Object.keys(modules).length,
    unavailableChecks: Object.entries(modules).filter(([, value]) => value && value.error).map(([key]) => key),
    authorizationRecorded: Boolean(scan.authorizationConfirmedAt && scan.scopeTarget),
  };
}

module.exports = { createAssessmentSummary, severityCounts, riskRating };

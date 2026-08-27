// OWASP Integration Service
// Maps findings to OWASP Testing Guide (WSTG) and checks ASVS compliance

// ── OWASP Testing Guide (WSTG v4.2) Mapping ──────────────────────────────────
// Maps vulnerability types to specific WSTG test procedures

const WSTG_MAPPING = {
  // Injection vulnerabilities
  'sql-injection': {
    tests: ['WSTG-INPV-05'],
    description: 'Testing for SQL Injection',
    severity: 'HIGH'
  },
  'command-injection': {
    tests: ['WSTG-INPV-12'],
    description: 'Testing for Command Injection',
    severity: 'HIGH'
  },
  'xss': {
    tests: ['WSTG-INPV-01', 'WSTG-INPV-02', 'WSTG-INPV-03'],
    description: 'Testing for Cross Site Scripting',
    severity: 'MEDIUM'
  },
  'path-traversal': {
    tests: ['WSTG-AUTHZ-01'],
    description: 'Testing Directory Traversal/file include',
    severity: 'HIGH'
  },
  'file-inclusion': {
    tests: ['WSTG-AUTHZ-01'],
    description: 'Testing Directory Traversal/file include',
    severity: 'HIGH'
  },
  
  // Authentication vulnerabilities
  'auth-bypass': {
    tests: ['WSTG-IDENT-04', 'WSTG-IDENT-05'],
    description: 'Testing for Account Enumeration and Guessable User Account',
    severity: 'HIGH'
  },
  'brute-force': {
    tests: ['WSTG-IDENT-03'],
    description: 'Testing for Weak lock out mechanism',
    severity: 'MEDIUM'
  },
  'weak-password': {
    tests: ['WSTG-IDENT-02'],
    description: 'Testing for Default Credentials',
    severity: 'HIGH'
  },
  'session-fixation': {
    tests: ['WSTG-SESS-03'],
    description: 'Testing for Session Fixation',
    severity: 'MEDIUM'
  },
  'session-hijack': {
    tests: ['WSTG-SESS-01', 'WSTG-SESS-02'],
    description: 'Testing for Session Management Schema',
    severity: 'HIGH'
  },
  
  // Configuration vulnerabilities
  'missing-headers': {
    tests: ['WSTG-CONF-02'],
    description: 'Testing for Default Applications and Configuration Issues',
    severity: 'LOW'
  },
  'directory-listing': {
    tests: ['WSTG-CONF-06'],
    description: 'Testing for MS Office/Macro File Content Extraction',
    severity: 'LOW'
  },
  'backup-files': {
    tests: ['WSTG-CONF-04'],
    description: 'Testing for Backup and Unreferenced Files',
    severity: 'MEDIUM'
  },
  'verbose-errors': {
    tests: ['WSTG-CONF-01'],
    description: 'Testing for Network Infrastructure Configuration',
    severity: 'LOW'
  },
  
  // Cryptographic vulnerabilities
  'weak-crypto': {
    tests: ['WSTG-CRYP-01'],
    description: 'Testing for Weak SSL/TLS Ciphers',
    severity: 'HIGH'
  },
  'ssl-poodle': {
    tests: ['WSTG-CRYP-01'],
    description: 'Testing for Weak SSL/TLS Ciphers',
    severity: 'HIGH'
  },
  'heartbleed': {
    tests: ['WSTG-CRYP-01'],
    description: 'Testing for Weak SSL/TLS Ciphers',
    severity: 'CRITICAL'
  },
  'weak-cert': {
    tests: ['WSTG-CRYP-01'],
    description: 'Testing for Weak SSL/TLS Ciphers',
    severity: 'HIGH'
  },
  
  // Service vulnerabilities (mapped from CVEs)
  'http-server-vuln': {
    tests: ['WSTG-CONF-02', 'WSTG-CONF-07'],
    description: 'Testing for Default Applications and Map File Examination',
    severity: 'HIGH'
  },
  'ftp-vuln': {
    tests: ['WSTG-CONF-09'],
    description: 'Testing for File Extension Handling',
    severity: 'MEDIUM'
  },
  'ssh-vuln': {
    tests: ['WSTG-CONF-02'],
    description: 'Testing for Default Applications',
    severity: 'HIGH'
  },
  'database-vuln': {
    tests: ['WSTG-INPV-05', 'WSTG-CONF-09'],
    description: 'Testing for SQL Injection and File Extension Handling',
    severity: 'HIGH'
  }
};

// CVE keyword to vulnerability type mapping
const CVE_KEYWORD_MAP = {
  'sql injection': 'sql-injection',
  'sqli': 'sql-injection',
  'command injection': 'command-injection',
  'rce': 'command-injection',
  'remote code execution': 'command-injection',
  'xss': 'xss',
  'cross-site scripting': 'xss',
  'path traversal': 'path-traversal',
  'directory traversal': 'path-traversal',
  'lfi': 'file-inclusion',
  'rfi': 'file-inclusion',
  'authentication bypass': 'auth-bypass',
  'auth bypass': 'auth-bypass',
  'brute force': 'brute-force',
  'default credentials': 'weak-password',
  'weak password': 'weak-password',
  'session fixation': 'session-fixation',
  'session hijack': 'session-hijack',
  'missing header': 'missing-headers',
  'security header': 'missing-headers',
  'directory listing': 'directory-listing',
  'backup file': 'backup-files',
  'verbose error': 'verbose-errors',
  'error disclosure': 'verbose-errors',
  'weak cipher': 'weak-crypto',
  'weak ssl': 'weak-crypto',
  'weak tls': 'weak-crypto',
  'poodle': 'ssl-poodle',
  'heartbleed': 'heartbleed',
  'certificate': 'weak-cert',
  'ssl': 'weak-crypto',
  'tls': 'weak-crypto',
  'apache': 'http-server-vuln',
  'nginx': 'http-server-vuln',
  'iis': 'http-server-vuln',
  'ftp': 'ftp-vuln',
  'vsftpd': 'ftp-vuln',
  'proftpd': 'ftp-vuln',
  'ssh': 'ssh-vuln',
  'openssh': 'ssh-vuln',
  'mysql': 'database-vuln',
  'postgresql': 'database-vuln',
  'mongodb': 'database-vuln',
  'mariadb': 'database-vuln'
};

// ── OWASP ASVS v4.0 Compliance Checks ─────────────────────────────────────────

const ASVS_REQUIREMENTS = {
  // V1: Architecture, Design and Threat Modeling
  'V1.1': {
    name: 'Secure Software Development Lifecycle',
    checks: [] // Not applicable for runtime scanning
  },
  
  // V2: Authentication
  'V2.1': {
    name: 'Authentication Security Requirements',
    checks: ['auth-mechanism', 'password-policy']
  },
  'V2.2': {
    name: 'Authentication General Security',
    checks: ['auth-bypass', 'brute-force']
  },
  'V2.5': {
    name: 'Credential Recovery and Reset',
    checks: ['weak-password']
  },
  
  // V3: Session Management
  'V3.1': {
    name: 'Session Management Security Requirements',
    checks: ['session-fixation', 'session-hijack']
  },
  'V3.2': {
    name: 'Session Binding',
    checks: ['session-fixation']
  },
  'V3.3': {
    name: 'Session Termination and Timeout',
    checks: ['session-fixation']
  },
  
  // V4: Access Control
  'V4.1': {
    name: 'General Access Control Design',
    checks: ['auth-bypass', 'privilege-escalation']
  },
  'V4.2': {
    name: 'Operation Level Access Control',
    checks: ['auth-bypass']
  },
  'V4.3': {
    name: 'Other Access Control Considerations',
    checks: ['path-traversal', 'file-inclusion']
  },
  
  // V5: Validation, Sanitization and Encoding
  'V5.1': {
    name: 'General Validation Design',
    checks: ['xss', 'sql-injection', 'command-injection']
  },
  'V5.2': {
    name: 'Sanitization and Sandboxing',
    checks: ['xss', 'command-injection']
  },
  'V5.3': {
    name: 'Output Encoding and Injection Prevention',
    checks: ['xss', 'sql-injection']
  },
  
  // V6: Stored Cryptography
  'V6.1': {
    name: 'Data Classification',
    checks: ['weak-crypto']
  },
  'V6.2': {
    name: 'Algorithms',
    checks: ['weak-crypto', 'ssl-poodle']
  },
  'V6.3': {
    name: 'Random Values',
    checks: [] // Hard to test via scan
  },
  
  // V7: Error Handling and Logging
  'V7.1': {
    name: 'General Logging',
    checks: [] // Hard to test via scan
  },
  'V7.3': {
    name: 'Log Protection',
    checks: ['verbose-errors']
  },
  
  // V8: Data Protection
  'V8.1': {
    name: 'General Data Protection',
    checks: ['weak-crypto']
  },
  'V8.2': {
    name: 'Client-side Data Storage',
    checks: [] // Hard to test via scan
  },
  'V8.3': {
    name: 'Sensitive Private Data',
    checks: ['weak-crypto']
  },
  
  // V9: Communication
  'V9.1': {
    name: 'Communication Security Requirements',
    checks: ['weak-crypto', 'ssl-poodle', 'heartbleed', 'weak-cert']
  },
  'V9.2': {
    name: 'Transport Layer Security',
    checks: ['weak-crypto', 'ssl-poodle', 'heartbleed', 'weak-cert']
  },
  
  // V10: Malicious Code
  'V10.1': {
    name: 'Code Integrity Controls',
    checks: [] // Hard to test via scan
  },
  
  // V11: Business Logic
  'V11.1': {
    name: 'Business Logic Security Requirements',
    checks: [] // Hard to test via scan
  },
  
  // V12: Files and Resources
  'V12.1': {
    name: 'File Upload',
    checks: [] // Requires application-specific testing
  },
  'V12.2': {
    name: 'File Integrity',
    checks: ['backup-files']
  },
  'V12.3': {
    name: 'File Execution',
    checks: ['file-inclusion', 'command-injection']
  },
  'V12.4': {
    name: 'File Storage',
    checks: ['path-traversal']
  },
  'V12.5': {
    name: 'File Download',
    checks: ['path-traversal']
  },
  'V12.6': {
    name: 'SSRF Protection',
    checks: [] // Requires application-specific testing
  },
  
  // V13: API and Web Service
  'V13.1': {
    name: 'General Web Service Security',
    checks: ['xss', 'sql-injection']
  },
  'V13.2': {
    name: 'RESTful Web Service',
    checks: ['auth-bypass', 'sql-injection']
  },
  'V13.3': {
    name: 'SOAP Web Service',
    checks: ['xss', 'sql-injection']
  },
  'V13.4': {
    name: 'GraphQL',
    checks: [] // Requires application-specific testing
  },
  
  // V14: Configuration
  'V14.1': {
    name: 'Build',
    checks: ['verbose-errors', 'directory-listing']
  },
  'V14.2': {
    name: 'Dependency',
    checks: ['http-server-vuln', 'database-vuln', 'ssh-vuln', 'ftp-vuln']
  },
  'V14.3': {
    name: 'Unintended Security Disclosure',
    checks: ['verbose-errors', 'backup-files']
  },
  'V14.4': {
    name: 'HTTP Security Headers',
    checks: ['missing-headers']
  },
  'V14.5': {
    name: 'HTTP Request Header Validation',
    checks: [] // Requires application-specific testing
  }
};

// ── Functions ─────────────────────────────────────────────────────────────────

/**
 * Map a CVE to WSTG test procedures
 */
function mapCVEtoWSTG(cve) {
  const tests = new Set();
  const descriptions = new Set();
  
  // Check CVE description for keywords
  const description = (cve.description || '').toLowerCase();
  const cveId = (cve.cveId || '').toLowerCase();
  
  for (const [keyword, vulnType] of Object.entries(CVE_KEYWORD_MAP)) {
    if (description.includes(keyword) || cveId.includes(keyword)) {
      const mapping = WSTG_MAPPING[vulnType];
      if (mapping) {
        mapping.tests.forEach(t => tests.add(t));
        descriptions.add(mapping.description);
      }
    }
  }
  
  // Check product/service
  const product = (cve.product || '').toLowerCase();
  for (const [keyword, vulnType] of Object.entries(CVE_KEYWORD_MAP)) {
    if (product.includes(keyword)) {
      const mapping = WSTG_MAPPING[vulnType];
      if (mapping) {
        mapping.tests.forEach(t => tests.add(t));
        descriptions.add(mapping.description);
      }
    }
  }
  
  return {
    tests: Array.from(tests),
    descriptions: Array.from(descriptions)
  };
}

/**
 * Map all CVEs to WSTG tests
 */
function mapAllCVEsToWSTG(vulnerabilities) {
  const wstgTests = {};
  
  for (const vuln of vulnerabilities) {
    const mapping = mapCVEtoWSTG(vuln);
    
    for (const test of mapping.tests) {
      if (!wstgTests[test]) {
        wstgTests[test] = {
          testId: test,
          description: mapping.descriptions.find(d => d) || 'Unknown',
          cves: [],
          severity: vuln.severity
        };
      }
      wstgTests[test].cves.push({
        cveId: vuln.cveId,
        product: vuln.product,
        version: vuln.version,
        cvssScore: vuln.cvssScore,
        severity: vuln.severity
      });
      
      // Update severity if this CVE is more severe
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0 };
      if (severityOrder[vuln.severity] > severityOrder[wstgTests[test].severity]) {
        wstgTests[test].severity = vuln.severity;
      }
    }
  }
  
  return Object.values(wstgTests);
}

/**
 * Check ASVS compliance based on findings
 */
function checkASVSCompliance(vulnerabilities, scanResults) {
  const compliance = {};
  
  // Initialize all requirements
  for (const [reqId, req] of Object.entries(ASVS_REQUIREMENTS)) {
    compliance[reqId] = {
      requirementId: reqId,
      name: req.name,
      status: 'PASS',
      findings: [],
      checks: req.checks
    };
  }
  
  // Check each vulnerability against ASVS requirements
  for (const vuln of vulnerabilities) {
    const wstgMapping = mapCVEtoWSTG(vuln);
    
    for (const [reqId, req] of Object.entries(ASVS_REQUIREMENTS)) {
      for (const check of req.checks) {
        const vulnType = getCVEVulnType(vuln);
        if (vulnType === check || wstgMapping.tests.some(t => req.checks.includes(t))) {
          compliance[reqId].status = 'FAIL';
          compliance[reqId].findings.push({
            cveId: vuln.cveId,
            product: vuln.product,
            version: vuln.version,
            severity: vuln.severity,
            cvssScore: vuln.cvssScore
          });
        }
      }
    }
  }
  
  // Check SSL/TLS findings from scan results
  if (scanResults.ssl) {
    const ssl = scanResults.ssl;
    
    // Check for weak protocols
    if (ssl.protocol && (ssl.protocol.includes('TLSv1.0') || ssl.protocol.includes('TLSv1.1') || ssl.protocol.includes('SSL'))) {
      compliance['V9.2'].status = 'FAIL';
      compliance['V9.2'].findings.push({
        type: 'weak-protocol',
        protocol: ssl.protocol,
        severity: 'HIGH'
      });
    }
    
    // Check certificate expiry
    if (ssl.daysToExpiry !== undefined) {
      if (ssl.daysToExpiry < 0) {
        compliance['V9.2'].status = 'FAIL';
        compliance['V9.2'].findings.push({
          type: 'expired-certificate',
          daysToExpiry: ssl.daysToExpiry,
          severity: 'CRITICAL'
        });
      } else if (ssl.daysToExpiry < 30) {
        compliance['V9.2'].status = 'WARN';
        compliance['V9.2'].findings.push({
          type: 'certificate-expiring-soon',
          daysToExpiry: ssl.daysToExpiry,
          severity: 'MEDIUM'
        });
      }
    }
  }
  
  // Check security headers
  if (scanResults.headers) {
    const headers = scanResults.headers;
    const missingHeaders = headers.missingSecurityHeaders || [];
    
    if (missingHeaders.length > 0) {
      compliance['V14.4'].status = 'FAIL';
      compliance['V14.4'].findings.push({
        type: 'missing-security-headers',
        headers: missingHeaders,
        severity: 'MEDIUM'
      });
    }
  }
  
  // Calculate overall compliance score
  const totalRequirements = Object.keys(compliance).length;
  const passedRequirements = Object.values(compliance).filter(r => r.status === 'PASS').length;
  const complianceScore = Math.round((passedRequirements / totalRequirements) * 100);
  
  return {
    complianceScore,
    totalRequirements,
    passedRequirements,
    failedRequirements: totalRequirements - passedRequirements,
    requirements: compliance
  };
}

/**
 * Get vulnerability type from CVE
 */
function getCVEVulnType(cve) {
  const description = (cve.description || '').toLowerCase();
  const product = (cve.product || '').toLowerCase();
  
  for (const [keyword, vulnType] of Object.entries(CVE_KEYWORD_MAP)) {
    if (description.includes(keyword) || product.includes(keyword)) {
      return vulnType;
    }
  }
  
  return 'unknown';
}

/**
 * Main function: Generate OWASP compliance report
 */
function generateOWASPReport(scanResults) {
  const vulnerabilities = scanResults.cve?.vulnerabilities || [];
  
  // Map CVEs to WSTG tests
  const wstgTests = mapAllCVEsToWSTG(vulnerabilities);
  
  // Check ASVS compliance
  const asvsCompliance = checkASVSCompliance(vulnerabilities, scanResults);
  
  return {
    owaspTestingGuide: {
      version: '4.2',
      totalTestsMapped: wstgTests.length,
      tests: wstgTests
    },
    asvsCompliance: {
      version: '4.0',
      score: asvsCompliance.complianceScore,
      totalRequirements: asvsCompliance.totalRequirements,
      passed: asvsCompliance.passedRequirements,
      failed: asvsCompliance.failedRequirements,
      requirements: asvsCompliance.requirements
    }
  };
}

module.exports = {
  generateOWASPReport,
  mapCVEtoWSTG,
  mapAllCVEsToWSTG,
  checkASVSCompliance,
  WSTG_MAPPING,
  ASVS_REQUIREMENTS,
  CVE_KEYWORD_MAP
};

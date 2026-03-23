#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');

const mandatoryFiles = [
  'ISO_READINESS_EVIDENCE.md',
  'ISO_STATEMENT_OF_APPLICABILITY_TEMPLATE.md',
  'RAILWAY_DEPLOYMENT_RUNBOOK.md',
  'compliance/MANDATORY_COMPLIANCE_CHECKLIST.md',
  'compliance/RISK_REGISTER.md',
  'compliance/INCIDENT_RESPONSE_RUNBOOK.md',
  'compliance/BUSINESS_CONTINUITY_AND_DRP.md',
  'compliance/ACCESS_CONTROL_POLICY.md',
  'compliance/DATA_CLASSIFICATION_AND_RETENTION.md',
  'compliance/SUPPLIER_SECURITY_REGISTER.md',
  'compliance/CHANGE_MANAGEMENT_POLICY.md'
];

const bannedPatterns = [
  /TakhleeAdmin@2024!/i,
  /TakhleeUser@2024!/i,
  /password\s*[:=]\s*['\"]?changeme['\"]?/i,
  /default\s+password/i
];

const markdownFilesToScan = [
  'README.md',
  'DETAILED_PROJECT_REPORT.md'
];

function validateFilePresence() {
  const missing = [];
  const empty = [];

  for (const relativePath of mandatoryFiles) {
    const absolutePath = path.join(rootDir, relativePath);
    if (!fs.existsSync(absolutePath)) {
      missing.push(relativePath);
      continue;
    }

    const stats = fs.statSync(absolutePath);
    if (!stats.isFile() || stats.size === 0) {
      empty.push(relativePath);
    }
  }

  return { missing, empty };
}

function scanForBannedCredentialPatterns() {
  const violations = [];

  for (const relativePath of markdownFilesToScan) {
    const absolutePath = path.join(rootDir, relativePath);
    if (!fs.existsSync(absolutePath)) {
      continue;
    }

    const content = fs.readFileSync(absolutePath, 'utf8');
    for (const pattern of bannedPatterns) {
      if (pattern.test(content)) {
        violations.push({ file: relativePath, pattern: pattern.toString() });
      }
    }
  }

  return violations;
}

function run() {
  const { missing, empty } = validateFilePresence();
  const credentialViolations = scanForBannedCredentialPatterns();

  if (missing.length === 0 && empty.length === 0 && credentialViolations.length === 0) {
    console.log('OK Mandatory compliance checks passed.');
    return;
  }

  if (missing.length > 0) {
    console.error('ERROR Missing mandatory compliance files:');
    missing.forEach((file) => console.error(`- ${file}`));
  }

  if (empty.length > 0) {
    console.error('ERROR Empty mandatory compliance files:');
    empty.forEach((file) => console.error(`- ${file}`));
  }

  if (credentialViolations.length > 0) {
    console.error('ERROR Banned credential patterns detected:');
    credentialViolations.forEach((violation) => {
      console.error(`- ${violation.file} matched ${violation.pattern}`);
    });
  }

  process.exit(1);
}

run();

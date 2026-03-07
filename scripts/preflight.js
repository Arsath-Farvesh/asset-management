#!/usr/bin/env node

require('dotenv').config();

const { validateEnvironment } = require('../src/config/env');

async function run() {
  const strictMode = process.argv.includes('--strict');
  const validation = validateEnvironment();

  if (validation.warnings.length > 0) {
    console.warn('\n⚠️  Environment Warnings:');
    validation.warnings.forEach((warning) => {
      console.warn(`- ${warning}`);
    });
  }

  if (validation.errors.length > 0) {
    console.error('\n❌ Environment Errors:');
    validation.errors.forEach((error) => {
      console.error(`- ${error}`);
    });
    process.exit(1);
  }

  if (strictMode && validation.warnings.length > 0) {
    console.error('\n❌ Strict mode enabled: warnings are treated as errors.');
    process.exit(1);
  }

  console.log('✅ Preflight checks passed.');
}

run().catch((error) => {
  console.error('❌ Preflight execution failed:', error.message);
  process.exit(1);
});

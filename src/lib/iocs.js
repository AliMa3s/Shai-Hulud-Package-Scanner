const MALICIOUS_SHA256 = [
  'de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6',
  '81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3',
  '83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e',
  '4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db',
  'dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c',
  '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09',
  'b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777',
  '86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b',
  'aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee'
];

const SUSPICIOUS_WORKFLOW_FILENAMES = [
  'shai-hulud-workflow.yml',
  'shai-hulud-workflow.yaml'
];

const SUSPICIOUS_POSTINSTALL_KEYWORDS = [
  'curl ',
  'wget ',
  'Invoke-WebRequest',
  'Invoke-RestMethod',
  'powershell',
  'PowerShell',
  'Start-Process',
  'node -e',
  'node -pe',
  'node -p',
  'npm exec',
  'npx ',
  'eval',
  'bash -c',
  'sh -c',
  'python -c',
  'perl -e',
  'fetch(',
  'certutil',
  'bitsadmin',
  'mshta',
  'msiexec',
  'ftp ',
  'tftp '
];

const SUSPICIOUS_CONTENT_PATTERNS = [
  {
    label: 'webhook.site exfiltration endpoint',
    severity: 'medium',
    pattern: /webhook\.site/i
  },
  {
    label: 'Known Shai-Hulud webhook GUID',
    severity: 'high',
    pattern: /bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/i
  },
  {
    label: 'Chalk/debug crypto theft helper',
    severity: 'high',
    pattern: /checkethereumw|runmask|newdlocal|_0x19ca67/i
  },
  {
    label: 'Shai-Hulud reference',
    severity: 'medium',
    pattern: /shai[-\s]?hulud/i
  },
  {
    label: 'Phishing helper domain',
    severity: 'medium',
    pattern: /npmjs\.help/i
  }
];

const TRUFFLEHOG_PATTERNS = [
  /trufflehog/i,
  /github\.com\/trufflesecurity\/trufflehog/i
];

const DEFAULT_DIR_EXCLUSIONS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.cache',
  '.tmp',
  'tmp',
  'logs',
  'coverage'
]);

const HASHABLE_EXTENSIONS = new Set(['.js', '.ts', '.cjs', '.mjs', '.jsx', '.tsx', '.json']);

const TEXT_FILE_EXTENSIONS = new Set([
  '.js',
  '.ts',
  '.cjs',
  '.mjs',
  '.jsx',
  '.tsx',
  '.json',
  '.yml',
  '.yaml',
  '.md',
  '.config',
  '.env',
  '.sh'
]);

module.exports = {
  MALICIOUS_SHA256,
  SUSPICIOUS_WORKFLOW_FILENAMES,
  SUSPICIOUS_POSTINSTALL_KEYWORDS,
  SUSPICIOUS_CONTENT_PATTERNS,
  TRUFFLEHOG_PATTERNS,
  DEFAULT_DIR_EXCLUSIONS,
  HASHABLE_EXTENSIONS,
  TEXT_FILE_EXTENSIONS
};

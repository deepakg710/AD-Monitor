import { getTopicByIdOrRule } from './catalog';
import type { MappingStatus } from './catalog';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  officialName: string;
  localRuleTitle: string;
  topicId: string;
  ruleId?: string;
  tactics: string[];
  mappingStatus: MappingStatus;
  rationale: string;
  reviewedDate: string;
  description: string;
  remediation: string[];
}

export const MITRE_MAPPINGS: Record<string, MitreTechnique> = {
  privilege_attack: {
    id: 'T1098',
    name: 'Account Manipulation',
    tactic: 'Persistence / Privilege Escalation',
    officialName: 'Account Manipulation',
    localRuleTitle: 'Privileged group change',
    topicId: 'privileged-group-change',
    ruleId: 'privilege_attack',
    tactics: ['Persistence', 'Privilege Escalation'],
    mappingStatus: 'Reviewed mapping',
    rationale: 'Adding accounts to privileged domain security groups directly matches T1098 Account Manipulation across Persistence and Privilege Escalation.',
    reviewedDate: '2026-10-03',
    description: 'Adversaries may manipulate accounts or security-enabled groups (such as Domain Admins or Administrators) to maintain or elevate access.',
    remediation: [
      'Confirm whether an approved change ticket exists for the group modification.',
      'Inspect SubjectUserName in Event 4728/4732 to identify who performed the change.',
      'Remove unauthorized accounts from privileged groups and rotate credentials if compromised.'
    ]
  },
  usb_copy: {
    id: 'T1052.001',
    name: 'Exfiltration Over Physical Medium: Exfiltration over USB',
    tactic: 'Exfiltration',
    officialName: 'Exfiltration Over Physical Medium: Exfiltration over USB',
    localRuleTitle: 'Possible USB data transfer',
    topicId: 'possible-usb-data-transfer',
    ruleId: 'usb_copy',
    tactics: ['Exfiltration'],
    mappingStatus: 'Reviewed mapping',
    rationale: 'Copying files to a removable USB storage device maps to T1052.001 when file-write or copy telemetry is present.',
    reviewedDate: '2026-10-03',
    description: 'Attempting to transfer confidential files off a managed workstation via removable USB flash or external storage.',
    remediation: [
      'Distinguish USB connection (mount) from actual file copy/write evidence.',
      'Check destination path, file names, and USB serial number in USB History.',
      'Verify business authorization with the employee and department manager.'
    ]
  },
  c2_beacon: {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
    officialName: 'Application Layer Protocol: Web Protocols',
    localRuleTitle: 'Possible periodic outbound activity',
    topicId: 'periodic-outbound-c2',
    ruleId: 'c2_beacon',
    tactics: ['Command and Control'],
    mappingStatus: 'Possible mapping',
    rationale: 'Recurring outbound connections can reflect C2 beaconing (T1071.001), but benign updaters and telemetry services also poll periodically.',
    reviewedDate: '2026-10-03',
    description: 'A process repeatedly contacts the same external destination on a regular interval with low timing jitter.',
    remediation: [
      'Identify the initiating process executable path and digital signature.',
      'Check destination IP/domain reputation and TLS certificate.',
      'Rule out benign background services before blocking or isolating.'
    ]
  },
  suspicious_powershell: {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    officialName: 'Command and Scripting Interpreter: PowerShell',
    localRuleTitle: 'Suspicious script activity',
    topicId: 'suspicious-script-activity',
    ruleId: 'suspicious_powershell',
    tactics: ['Execution'],
    mappingStatus: 'Reviewed mapping',
    rationale: 'PowerShell script block and command-line auditing directly observe T1059.001 Execution.',
    reviewedDate: '2026-10-03',
    description: 'PowerShell execution using encoded commands (-EncodedCommand), download cradles, or execution policy bypass flags.',
    remediation: [
      'Decode any Base64 payload and review Event ID 4104 Script Block text.',
      'Inspect parent process and subsequent network or file events.',
      'Verify whether an IT administrator ran an approved automation script.'
    ]
  },
  restricted: {
    id: 'T1039',
    name: 'Data from Network Shared Drive',
    tactic: 'Collection / Discovery',
    officialName: 'Data from Network Shared Drive',
    localRuleTitle: 'Unauthorized file access',
    topicId: 'restricted-access',
    ruleId: 'restricted',
    tactics: ['Collection', 'Discovery'],
    mappingStatus: 'Possible mapping',
    rationale: 'Attempting to read departmental files on an SMB share aligns with T1039 (Data from Network Shared Drive) and T1083 (File and Directory Discovery), not Lateral Movement (T1021.002).',
    reviewedDate: '2026-10-03',
    description: 'An account attempts to access a restricted departmental folder or file outside its permitted role (such as Sales accessing HR).',
    remediation: [
      'Check whether the access attempt was denied by NTFS ACLs or succeeded.',
      'Verify the employee department and group memberships in Active Directory.',
      'Review whether the attempt was an accidental click or repeated probing.'
    ]
  },
  canary: {
    id: 'No direct mapping',
    name: 'Defensive Honeytoken / Tripwire Concept',
    tactic: 'Collection / Discovery',
    officialName: 'Defensive Honeytoken / Tripwire Concept',
    localRuleTitle: 'Canary / decoy file access',
    topicId: 'canary-decoy-access',
    ruleId: 'canary',
    tactics: ['Collection', 'Discovery'],
    mappingStatus: 'No direct mapping',
    rationale: 'A canary file is a defensive deception control rather than an adversary technique. Touching it may occur during T1083 or T1039 activity.',
    reviewedDate: '2026-10-03',
    description: 'Access recorded on a planted decoy document that has no legitimate operational workflow.',
    remediation: [
      'Confirm which process opened the decoy file (interactive app vs. background indexer).',
      'Review surrounding file reads and directory browsing by the same session.',
      'Interview the account holder if interactive access is confirmed.'
    ]
  },
  bulk: {
    id: 'T1039',
    name: 'Data from Network Shared Drive / Local System (T1005)',
    tactic: 'Collection',
    officialName: 'Data from Network Shared Drive / Local System (T1005)',
    localRuleTitle: 'Unusual bulk file reads',
    topicId: 'bulk-sensitive-reads',
    ruleId: 'bulk',
    tactics: ['Collection'],
    mappingStatus: 'Reviewed mapping',
    rationale: 'Reading large numbers of shared or local files maps to T1039 (Data from Network Shared Drive) and T1005 (Data from Local System). Repaired from erroneous T1095.',
    reviewedDate: '2026-10-03',
    description: 'An account reads a high volume of sensitive files within a short window, exceeding normal operational thresholds.',
    remediation: [
      'Review the list of accessed files and the process that opened them.',
      'Check for subsequent archive creation (staging) or removable media writes.',
      'Confirm whether the user was performing legitimate search, backup, or reporting.'
    ]
  },
  staging: {
    id: 'T1074.001',
    name: 'Data Staged: Local Data Staging',
    tactic: 'Collection',
    officialName: 'Data Staged: Local Data Staging',
    localRuleTitle: 'Archive or staging activity',
    topicId: 'archive-staging-activity',
    ruleId: 'staging',
    tactics: ['Collection'],
    mappingStatus: 'Possible mapping',
    rationale: 'Collecting files into a staging directory or archive maps to T1074.001 (and T1560 Archive Collected Data). Process launch alone does not prove archive contents.',
    reviewedDate: '2026-10-03',
    description: 'Files are gathered into a temporary directory or compressed into an archive (such as .zip or .7z).',
    remediation: [
      'Inspect command-line arguments or source-to-archive file correlation.',
      'Check whether sensitive shares were read immediately prior to archive creation.',
      'Look for subsequent USB copy or outbound network transfer.'
    ]
  },
  antivirus: {
    id: 'No direct mapping',
    name: 'Security Product Alert (Windows Defender)',
    tactic: 'Execution / Defense Evasion',
    officialName: 'Security Product Alert (Windows Defender)',
    localRuleTitle: 'Antivirus / Defender detection',
    topicId: 'antivirus-defender-detection',
    ruleId: 'antivirus',
    tactics: ['Execution', 'Defense Evasion'],
    mappingStatus: 'No direct mapping',
    rationale: 'An antivirus detection (Event 1116/1117) is a defensive product alert rather than a single ATT&CK technique. Disabling Defender maps separately to T1562.001.',
    reviewedDate: '2026-10-03',
    description: 'Windows Defender Antivirus reported a malware, PUA, or suspicious file detection on the endpoint.',
    remediation: [
      'Verify Event ID 1117 to confirm whether Defender quarantined or blocked the file.',
      'Identify the file path, hash, and originating process.',
      'Check whether the detection was an authorized EICAR lab test or real threat.'
    ]
  },
  failed_logon: {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    officialName: 'Brute Force',
    localRuleTitle: 'Wrong password & logon failures',
    topicId: 'auth-failures-logons',
    ruleId: 'failed_logon',
    tactics: ['Credential Access'],
    mappingStatus: 'Possible mapping',
    rationale: 'Applies conditionally when repeated authentication failures result from systematic password guessing rather than normal user typos or cached credentials.',
    reviewedDate: '2026-10-04',
    description: 'Wrong password attempts or failed sign-in events occur for an account and are counted in a sliding window.',
    remediation: [
      'Check the live wrong-password attempt counter and SubStatus code (0xC000006A / 0x18 wrong password vs. 0xC0000234 lockout).',
      'Confirm with the employee whether they mistyped their password at the workstation.',
      'Inspect Event Explorer for any subsequent successful logon (Event 4624) after the failures.'
    ]
  }
};

export function getMitre(ruleId?: string): MitreTechnique | null {
  if (!ruleId) return null;
  if (MITRE_MAPPINGS[ruleId]) return MITRE_MAPPINGS[ruleId];
  const topic = getTopicByIdOrRule(ruleId);
  if (!topic) return null;
  const firstTech = topic.mitre.techniques[0];
  const idStr = firstTech ? firstTech.id : 'No direct mapping';
  const offName = firstTech ? firstTech.officialName : 'Behavioral / Policy Rule';
  const tacs = firstTech ? firstTech.tactics : [topic.category];
  return {
    id: idStr,
    name: offName,
    tactic: tacs.join(' / '),
    officialName: offName,
    localRuleTitle: topic.shortTitle || topic.title,
    topicId: topic.id,
    ruleId: topic.ruleId || undefined,
    tactics: tacs,
    mappingStatus: topic.mitre.mappingStatus,
    rationale: topic.mitre.rationale,
    reviewedDate: topic.mitre.reviewDate,
    description: topic.shortMeaning,
    remediation: topic.whatToCheckNext.map(w => w.text)
  };
}

export interface MitreMatrixColumn {
  id: string;
  name: string;
  items: {
    techId: string;
    officialName: string;
    localTitle: string;
    topicId: string;
    ruleId?: string;
    mappingStatus: MappingStatus;
    implemented: boolean;
  }[];
}

export const MITRE_TACTICS: MitreMatrixColumn[] = [
  {
    id: 'TA0001 / TA0006',
    name: 'Access & Credential Abuse',
    items: [
      {
        techId: 'T1110',
        officialName: 'Brute Force',
        localTitle: 'Wrong password & logon failures',
        topicId: 'auth-failures-logons',
        ruleId: 'failed_logon',
        mappingStatus: 'Possible mapping',
        implemented: true
      },
      {
        techId: 'T1078',
        officialName: 'Valid Accounts',
        localTitle: 'After-hours sensitive file access',
        topicId: 'after-hours-sensitive',
        ruleId: 'after_hours',
        mappingStatus: 'Possible mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0002',
    name: 'Execution',
    items: [
      {
        techId: 'T1059.001',
        officialName: 'Command & Scripting: PowerShell',
        localTitle: 'Suspicious script activity',
        topicId: 'suspicious-script-activity',
        ruleId: 'suspicious_powershell',
        mappingStatus: 'Reviewed mapping',
        implemented: true
      },
      {
        techId: 'T1059.003',
        officialName: 'Windows Command Shell',
        localTitle: 'Unusual built-in tool execution',
        topicId: 'lolbin-execution',
        ruleId: 'lolbin',
        mappingStatus: 'Possible mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0003 / TA0004',
    name: 'Persistence & Privilege Escalation',
    items: [
      {
        techId: 'T1098',
        officialName: 'Account Manipulation',
        localTitle: 'Privileged group change',
        topicId: 'privileged-group-change',
        ruleId: 'privilege_attack',
        mappingStatus: 'Reviewed mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    items: [
      {
        techId: 'T1562.001',
        officialName: 'Impair Defenses: Disable or Modify Tools',
        localTitle: 'Security-control change',
        topicId: 'security-control-change',
        mappingStatus: 'Reviewed mapping',
        implemented: false
      },
      {
        techId: 'T1218',
        officialName: 'System Binary Proxy Execution',
        localTitle: 'Unusual built-in tool execution',
        topicId: 'lolbin-execution',
        ruleId: 'lolbin',
        mappingStatus: 'Possible mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0007 / TA0008',
    name: 'Discovery & Lateral Movement',
    items: [
      {
        techId: 'T1083 / T1039',
        officialName: 'File and Directory Discovery / Network Share',
        localTitle: 'Unauthorized file access',
        topicId: 'restricted-access',
        ruleId: 'restricted',
        mappingStatus: 'Possible mapping',
        implemented: true
      },
      {
        techId: 'T1021.001 / .002',
        officialName: 'Remote Services: RDP & SMB Admin Shares',
        localTitle: 'Unexpected remote access',
        topicId: 'lateral-movement-remote',
        mappingStatus: 'Possible mapping',
        implemented: false
      }
    ]
  },
  {
    id: 'TA0009',
    name: 'Collection',
    items: [
      {
        techId: 'T1039 / T1005',
        officialName: 'Data from Network Shared Drive / Local System',
        localTitle: 'Unusual bulk file reads',
        topicId: 'bulk-sensitive-reads',
        ruleId: 'bulk',
        mappingStatus: 'Reviewed mapping',
        implemented: true
      },
      {
        techId: 'T1074.001 / T1560',
        officialName: 'Local Data Staging / Archive Collected Data',
        localTitle: 'Archive or staging activity',
        topicId: 'archive-staging-activity',
        ruleId: 'staging',
        mappingStatus: 'Possible mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0011 / TA0010',
    name: 'Command & Control / Exfiltration',
    items: [
      {
        techId: 'T1071.001',
        officialName: 'Application Layer Protocol: Web Protocols',
        localTitle: 'Possible periodic outbound activity',
        topicId: 'periodic-outbound-c2',
        ruleId: 'c2_beacon',
        mappingStatus: 'Possible mapping',
        implemented: true
      },
      {
        techId: 'T1052.001',
        officialName: 'Exfiltration Over Physical Medium: USB',
        localTitle: 'Possible USB data transfer',
        topicId: 'possible-usb-data-transfer',
        ruleId: 'usb_copy',
        mappingStatus: 'Reviewed mapping',
        implemented: true
      }
    ]
  },
  {
    id: 'TA0040 / DEF',
    name: 'Impact & Defensive Tripwires',
    items: [
      {
        techId: 'T1486 / T1485',
        officialName: 'Data Encrypted for Impact / Data Destruction',
        localTitle: 'Rapid file modification or deletion',
        topicId: 'rapid-file-modification-deletion',
        ruleId: 'rapid_change',
        mappingStatus: 'Possible mapping',
        implemented: true
      },
      {
        techId: 'No direct mapping',
        officialName: 'Defensive Tripwire & AV Product Alerts',
        localTitle: 'Canary file access & Defender alerts',
        topicId: 'canary-decoy-access',
        ruleId: 'canary',
        mappingStatus: 'No direct mapping',
        implemented: true
      }
    ]
  }
];

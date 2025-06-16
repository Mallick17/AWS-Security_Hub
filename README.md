# AWS Security Hub
AWS **Security Hub** is a **cloud security posture management (CSPM)** service that **centralizes and automates security checks** across your AWS environment. It aggregates findings from AWS services and supported third-party tools, evaluates compliance against multiple standards, and helps you **identify, prioritize, and respond to security risks**.

> The Security Hub provides a single place in the AWS environment to aggregate, organize, and prioritize security alerts and discoveries from multiple AWS security services. This may be Amazon GuardDuty, Amazon Inspector, Amazon Macie, IAM, Access Analyzer, AWS Firewall Manager. But it also supports third-party partner products.

![image](https://github.com/user-attachments/assets/93e97d18-4cd9-4547-83a7-9e271cd004ce)

---

### [Key Concepts - Refer the Documentation For Now](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-concepts.html) 
- Detailed explain on the way to be prepared.

---

## 📌 What Are Security Standards in Security Hub?

Security standards in AWS Security Hub are **automated compliance frameworks** that consist of **security controls** (automated checks) designed to enforce **best practices** in cloud security. Each **enabled standard** will:

* Continuously **evaluate your AWS account and resources**,
* Generate **control findings** if a check fails,
* Help you assess and maintain **security compliance**,
* Provide **security scores** to measure posture across accounts.

---

## ✅ Current Supported Security Standards (As of 2025)

| Security Standard                                   | Type       | Purpose                                                                                               | Defined By                         |
| --------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **AWS Foundational Security Best Practices (FSBP)** | AWS native | Secure core AWS services and accounts                                                                 | AWS Security Experts               |
| **CIS AWS Foundations Benchmark**                   | External   | Enforce cloud infrastructure hygiene and secure configurations                                        | Center for Internet Security (CIS) |
| **PCI DSS v3.2.1**                                  | Compliance | Secure credit card data for companies accepting, processing, storing, or transmitting cardholder data | PCI Security Standards Council     |
| **NIST SP 800-53 Rev 5**                            | Government | Framework for securing information systems used by U.S. federal agencies                              | NIST (U.S. Gov)                    |
| **NIST Cybersecurity Framework (CSF)**              | Government | Risk-based framework for organizations to manage and reduce cybersecurity risk                        | NIST                               |

---

## 1️⃣ AWS Foundational Security Best Practices (FSBP)

### 📖 What It Is:

The **AWS Foundational Security Best Practices** standard is a curated set of **automated checks** that enforce **AWS-recommended configurations** for key AWS services like:

* S3, IAM, EC2, RDS, Lambda, CloudTrail, etc.

### 🧠 Why It Is Used:

* To ensure your **AWS configurations follow security best practices** as defined by AWS security engineers.
* Helps teams **reduce the attack surface** in day-to-day deployments.

### 🧪 What It Checks:

* IAM users with active access keys older than 90 days
* Public S3 buckets
* Unencrypted EBS volumes
* VPCs with open security groups (0.0.0.0/0)
* CloudTrail not enabled
* Unrestricted Lambda permissions
* RDS instances without backups

### 📍 Where It Is Used:

* All production, staging, and dev environments in AWS
* Used by **organizations of any size** looking to harden their AWS deployments

---

## 2️⃣ CIS AWS Foundations Benchmark

### 📖 What It Is:

The **Center for Internet Security (CIS)** Benchmark is an **independent** security framework specifically tailored to **AWS infrastructure**. Security Hub supports the **Level 1 controls** from this benchmark.

### 🧠 Why It Is Used:

* To validate your AWS configuration aligns with **independent industry-standard benchmarks**
* Frequently used by organizations preparing for **audits or external certifications**

### 🧪 What It Checks:

* Root account not used
* MFA enabled for root user
* IAM policies follow least privilege
* IAM password policies have minimum strength
* Security groups not open to 0.0.0.0/0
* CloudTrail and Config enabled
* S3 buckets logging and encryption enabled

### 📍 Where It Is Used:

* Organizations undergoing **internal or third-party security audits**
* Companies following **compliance-driven development** models

---

## 3️⃣ PCI DSS v3.2.1

### 📖 What It Is:

The **Payment Card Industry Data Security Standard (PCI DSS)** is a global compliance standard for **handling credit card data**. Security Hub maps AWS checks to portions of this standard.

### 🧠 Why It Is Used:

* To maintain **PCI compliance** for organizations dealing with cardholder data
* To ensure customer financial information is **protected and secured**

### 🧪 What It Checks:

* Encrypted storage of sensitive data
* Segmentation of public/private networks
* IAM access controls for cardholder data
* Logging and monitoring of data access
* Secure transmission (TLS)
* Key management and rotation policies

### 📍 Where It Is Used:

* **E-commerce platforms**
* SaaS providers that handle **online payments**
* Fintech or POS solution vendors

---

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

---

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

---

## 📊 Comparison Table of Security Standards

| Standard        | Managed By  | Purpose                              | Coverage                           | Compliance Scope                       | Ideal For                                 |
| --------------- | ----------- | ------------------------------------ | ---------------------------------- | -------------------------------------- | ----------------------------------------- |
| **FSBP**        | AWS         | Secure AWS resource configurations   | 50+ AWS services                   | AWS-native security hardening          | All AWS users                             |
| **CIS**         | CIS         | Harden cloud accounts and IAM access | Basic AWS setup                    | General best practices                 | Audit-readiness                           |
| **PCI DSS**     | PCI Council | Protect cardholder data              | Payment-related services           | Required for credit card data handling | E-commerce, fintech                       |
| **NIST 800-53** | NIST        | Align with U.S. government controls  | Broad controls for federal systems | U.S. federal standards                 | Gov contractors, compliance-heavy sectors |
| **NIST CSF**    | NIST        | Risk-based cybersecurity program     | Framework-driven                   | Customizable                           | Organizations building custom programs    |

---

## 🧠 Bonus: How Security Hub Uses These Standards

* You can **enable one or more standards per account or per Region**.
* Security Hub **evaluates controls automatically** on a scheduled basis (usually every 12–24 hours).
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

## 📚 Supported Security Standards

Security Hub supports **multiple security frameworks**, each with its own set of controls:

| Standard Name                                       | Description                                                                                  |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **AWS Foundational Security Best Practices (FSBP)** | AWS-created standard with best practices for securing AWS services.                          |
| **CIS AWS Foundations Benchmark**                   | Developed by the Center for Internet Security; focuses on secure AWS configuration.          |
| **PCI DSS**                                         | Ensures compliance with Payment Card Industry standards for handling credit card data.       |
| **NIST CSF**                                        | Aligns with the U.S. National Institute of Standards and Technology Cybersecurity Framework. |

When a standard is **enabled**:

* Its **controls are evaluated automatically**.
* **Failed controls generate findings**, visible in the Security Hub console.
* The **security score** reflects how compliant your account is with the standard.

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

---

## 🗃️ Data Handling Notes

* **Findings Format**: Security Hub uses a consistent JSON format called **ASFF (AWS Security Finding Format)**.
* **Data Retention**: Findings are retained for **90 days** (unless exported).
* **Multi-Region Support**: You can configure cross-region aggregation for a global view.

---


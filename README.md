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

## Current Supported Security Standards (As of 2025)

| Security Standard                                   | Type       | Purpose                                                                                               | Defined By                         |
| --------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **AWS Foundational Security Best Practices (FSBP)** | AWS native | Secure core AWS services and accounts                                                                 | AWS Security Experts               |
| **CIS AWS Foundations Benchmark**                   | External   | Enforce cloud infrastructure hygiene and secure configurations                                        | Center for Internet Security (CIS) |
| **PCI DSS v3.2.1**                                  | Compliance | Secure credit card data for companies accepting, processing, storing, or transmitting cardholder data | PCI Security Standards Council     |
| **NIST SP 800-53 Rev 5**                            | Government | Framework for securing information systems used by U.S. federal agencies                              | NIST (U.S. Gov)                    |
| **NIST Cybersecurity Framework (CSF)**              | Government | Risk-based framework for organizations to manage and reduce cybersecurity risk                        | NIST                               |

---

<details>
 <summary>1. AWS Foundational Security Best Practices (FSBP)</summary>

## 1️⃣ AWS Foundational Security Best Practices (FSBP)

### Description and Purpose:
- FSBP is a compilation of security best practices developed by AWS and industry professionals, suitable for organizations of all sectors and sizes.
- It aims to detect when your AWS accounts and deployed resources deviate from security best practices, offering prescriptive guidance to improve and maintain your security posture.
- This standard covers AWS’s most popular and foundational services, ensuring a broad scope of security checks.
- The **AWS Foundational Security Best Practices** standard is a curated set of **automated checks** that enforce **AWS-recommended configurations** for key AWS services like:
* S3, IAM, EC2, RDS, Lambda, CloudTrail, etc.

### Why It Is Used:
* To ensure your **AWS configurations follow security best practices** as defined by AWS security engineers.
* Helps teams **reduce the attack surface** in day-to-day deployments.

### Importance:
- FSBP is essential for establishing a strong security foundation in AWS. It helps prevent common misconfigurations and vulnerabilities, making it a great starting point for beginners.
- By following FSBP, you can align your environment with AWS-recommended practices, reducing the risk of security breaches.

### 🧪 What It Checks:
- FSBP includes a wide range of controls, each checking a specific aspect of your AWS setup. Here are some examples:
  - _**Account.1:**_ Ensures security contact information is provided for an AWS account, so AWS can notify you in case of security issues.
  - _**ACM.1:**_ Checks if imported and ACM-issued certificates are renewed after a specified time period, ensuring secure communication.
  - **_APIGateway.1:_** Verifies that API Gateway REST and WebSocket API execution logging is enabled, important for monitoring and auditing.
  - **_AutoScaling.2:_** Ensures Auto Scaling groups are spread across multiple Availability Zones, improving reliability and security.
  - **_CloudFront.1:_** Checks if CloudFront distributions have a default root object configured, preventing misconfigurations.
  - **_RDS.1:_** Ensures Amazon RDS databases are encrypted at rest, protecting data even when not in use. RDS instances without backups.

### 📍 Where It Is Used:

* All production, staging, and dev environments in AWS
* Used by **organizations of any size** looking to harden their AWS deployments

</details>



<details>
 <summary>2. CIS AWS Foundations Benchmark</summary>

## 2️⃣ CIS AWS Foundations Benchmark

### 📖 What It Is:

The **Center for Internet Security (CIS)** Benchmark is an **independent** security framework specifically tailored to **AWS infrastructure**. Security Hub supports the **Level 1 controls** from this benchmark.

### 🧠 Why It Is Used:

* To validate your AWS configuration aligns with **independent industry-standard benchmarks**
* Frequently used by organizations preparing for **audits or external certifications**

### 🧪 What It Checks:
- The CIS Benchmark includes controls that focus on key security areas. Examples include:
  - **_Avoid the use of the "root" account:_** Ensures you don’t use the root account for daily tasks, as it has full access and poses a high risk if compromised.
  - **_Ensure credentials unused for 90 days or more are disabled:_** Prevents old, unused accounts from being exploited, enhancing security.
  - **_Ensure IAM password policy requires a minimum length of 14 or greater:_** Enforces strong passwords, making them harder to guess or crack.
  - **_Ensure MFA is enabled for the "root" account:_** Adds an extra layer of security by requiring a second authentication factor.
  - **_Ensure no security groups allow ingress from 0.0.0.0/0 to port 22_**: Prevents public access to SSH, reducing the risk of unauthorized access to EC2 instances.
  - **_Ensure rotation for customer-created KMS keys is enabled:_** Ensures encryption keys are rotated regularly, improving security for encrypted data.

### 📍 Where It Is Used:

* Organizations undergoing **internal or third-party security audits**
* Companies following **compliance-driven development** models

</details>



<details>
 <summary>3. PCI DSS v3.2.1</summary>

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


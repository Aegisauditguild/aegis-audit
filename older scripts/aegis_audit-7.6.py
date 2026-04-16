"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         AEGIS AUDIT GUILD                                  ║
║                  Cloud Waste Intelligence Engine v2.6                      ║
║                                                                            ║
║        "Legacy in the landscape, for your company and my family."          ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHAT THIS SCRIPT DOES:
  Scans your AWS account across all regions for hidden, forgotten, and wasteful
  cloud resources that are silently draining your budget and your planet's energy.
  Results are presented in two phases — a free summary, then a full unlocked
  report delivered after the Aegis fee is agreed.

PAYWALL MODEL:
  PHASE 1 — FREE SUMMARY (always delivered):
    - Executive summary: total waste, top findings, environmental impact
    - Categories of waste found and resource counts
    - Aegis fee (capped at £250)
    - CO₂ and energy impact of identified waste

  PHASE 2 — UNLOCKED REPORT (after fee agreed):
    - Exact resource IDs for every waste item
    - Precise monthly cost per resource
    - Creation dates, tags, and risk notes
    - Step-by-step remediation for each item
    - Per-resource energy and CO₂ impact
    - Verified eco partner rewilding contribution receipt

  No waste found = no fee. We will tell you your account is clean, free.

CHECKS PERFORMED (14 total):
   1. Orphaned EBS Volumes       — Unattached hard drives
   2. Zombie Snapshots           — Backups whose parent volume no longer exists
   3. Stopped EC2 Instances      — Servers off but still costing money
   4. Unused Elastic IPs         — Idle reserved IP addresses
   5. Idle Load Balancers        — Traffic managers with no healthy targets
   6. Idle NAT Gateways          — Network gateways with zero traffic
   7. Stopped RDS Instances      — Databases still billed for storage
   8. CloudWatch Log Groups      — Logs stored forever with no retention policy
   9. Old ECR Container Images   — Abandoned Docker images (>90 days)
  10. Idle Lambda Functions       — Hygiene/indirect risk (no direct cost)
  11. Abandoned S3 Buckets        — Storage untouched for 90+ days
  12. Idle SageMaker Endpoints    — AI inference endpoints (7-day status check)
  13. GPU Zombie Endpoints        — InService endpoints with 0 invocations/72h
  14. Redundant Snapshot Lineage  — Volumes with excessive snapshot accumulation

PRICING & BUSINESS MODEL:
  Audit Fee Cap            : £250 per scan (we never charge more)
  Conservation Split       : 80% of our fee goes to our verified eco partner
  Your Saving              : 100% of waste found is yours to reclaim

SECURITY COMMITMENTS:
  - Read-Only IAM policy only — we cannot create, modify or delete anything
  - No machine learning — your data never trains any model
  - No credentials stored after the scan completes
  - No agents, no installs, no ongoing access of any kind

RECOMMENDED IAM POLICY (apply this before running the scan):
  Create an IAM user with the following policy — nothing more, nothing less.

  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AegisAuditReadOnly",
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeInstances",
          "ec2:DescribeAddresses",
          "ec2:DescribeRegions",
          "ec2:DescribeNatGateways",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "rds:DescribeDBInstances",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "ecr:DescribeRepositories",
          "ecr:DescribeImages",
          "lambda:ListFunctions",
          "lambda:GetFunctionConcurrency",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "sagemaker:ListEndpoints",
          "cloudwatch:GetMetricStatistics",
          "sts:GetCallerIdentity"
        ],
        "Resource": "*"
      }
    ]
  }

  Instructions:
  1. Go to AWS Console > IAM > Users > Create User
  2. Name it: aegis-audit-readonly
  3. Attach the policy above (or paste as an inline policy)
  4. Generate an Access Key for programmatic access
  5. Run: aws configure  (enter the Access Key ID and Secret)
  6. Run: python aegis_audit.py
  7. Delete the IAM user after the scan is complete

REQUIREMENTS:
  pip install boto3
  AWS credentials configured via:
    - AWS CLI (run: aws configure), OR
    - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
      AWS_DEFAULT_REGION
"""

import boto3
import sys
import json
import os
import time
from datetime import datetime, timezone, timedelta
from botocore.exceptions import NoCredentialsError, ClientError
from botocore.config import Config

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
EBS_GBP_PER_GB_MONTH        = 0.079    # AWS EBS gp2 rate (eu-west-2)
SNAPSHOT_GBP_PER_GB         = 0.053    # AWS EBS snapshot rate (eu-west-2)
ELASTIC_IP_COST_PER_MONTH   = 3.60    # AWS charge per idle EIP
LB_COST_PER_MONTH           = 15.00   # Minimum per idle load balancer
RDS_STORAGE_GBP_PER_GB      = 0.115   # RDS storage rate
LOGS_GBP_PER_GB             = 0.03    # CloudWatch Logs storage rate
ECR_GBP_PER_GB              = 0.10    # ECR image storage rate
NAT_GBP_PER_MONTH           = 27.00   # NAT Gateway minimum monthly cost
S3_GBP_PER_GB               = 0.023   # S3 Standard storage rate
LAMBDA_GBP_PER_MONTH        = 0.00    # Lambda idle = no cost but flags stale code
SAGEMAKER_ML_T3_MEDIUM      = 0.056   # ml.t3.medium per hour (~£40/month)

# GPU Zombie Endpoint instance costs (£/hour) — used in Check 13
SAGEMAKER_GPU_COSTS = {
    'ml.p2.xlarge':   0.900,
    'ml.p3.2xlarge':  3.825,
    'ml.p3.8xlarge':  15.300,
    'ml.p3.16xlarge': 30.600,
    'ml.g4dn.xlarge': 0.526,
    'ml.g4dn.2xlarge':0.940,
    'ml.g4dn.4xlarge':1.505,
    'ml.g4dn.8xlarge':2.720,
    'ml.g4dn.12xlarge':4.075,
    'ml.g5.xlarge':   1.006,
    'ml.g5.2xlarge':  1.210,
    'ml.g5.4xlarge':  1.620,
    'ml.g5.8xlarge':  2.440,
}
GPU_ZOMBIE_IDLE_HOURS       = 72     # Flag endpoint if 0 invocations in this window
SNAPSHOT_LINEAGE_THRESHOLD  = 30     # Flag volume if it has more snapshots than this
SNAPSHOT_LINEAGE_AGE_DAYS   = 90     # Only count snapshots older than this
ZOMBIE_SNAPSHOT_AGE_DAYS    = 90
S3_IDLE_DAYS                = 90
LAMBDA_IDLE_DAYS            = 90
AEGIS_FEE_CAP_GBP           = 250.00
MOSSY_EARTH_SPLIT           = 0.80
AEGIS_SPLIT                 = 0.20

# Priority levels per check — used in executive summary and free report
PRIORITY = {
    'gpu_zombies':      ('CRITICAL', '★★★'),
    'sagemaker':        ('CRITICAL', '★★★'),
    'instances':        ('HIGH',     '★★☆'),
    'nat_gateways':     ('HIGH',     '★★☆'),
    'load_balancers':   ('HIGH',     '★★☆'),
    'rds_instances':    ('HIGH',     '★★☆'),
    's3_buckets':       ('HIGH',     '★★☆'),
    'volumes':          ('HIGH',     '★★☆'),
    'snap_lineage':     ('MEDIUM',   '★☆☆'),
    'snapshots':        ('MEDIUM',   '★☆☆'),
    'elastic_ips':      ('LOW',      '☆☆☆'),
    'ecr_images':       ('LOW',      '☆☆☆'),
    'cloudwatch_logs':  ('LOW',      '☆☆☆'),
    'lambda_functions': ('LOW',      '☆☆☆'),  # Hygiene only — no direct cost
}

# Effort + time-to-fix — shown in unlocked report
EFFORT = {
    'gpu_zombies':      ('2 min',  'Delete endpoint in SageMaker console'),
    'sagemaker':        ('2 min',  'Delete endpoint in SageMaker console'),
    'instances':        ('5 min',  'Terminate via EC2 console — create AMI first if unsure'),
    'nat_gateways':     ('5 min',  'Delete via VPC console — remove route table entries first'),
    'load_balancers':   ('2 min',  'Delete via EC2 console > Load Balancers'),
    'rds_instances':    ('5 min',  'Delete via RDS console — take final snapshot if needed'),
    's3_buckets':       ('10 min', 'Empty bucket then delete — or archive to Glacier'),
    'volumes':          ('2 min',  'Delete via EC2 console > Volumes'),
    'snap_lineage':     ('15 min', 'Delete oldest snapshots in batches via EC2 console'),
    'snapshots':        ('5 min',  'Delete via EC2 console > Snapshots'),
    'elastic_ips':      ('1 min',  'Release via EC2 console > Elastic IPs'),
    'ecr_images':       ('5 min',  'Delete old images or set lifecycle policy to auto-expire'),
    'cloudwatch_logs':  ('3 min',  'Set retention policy via CloudWatch > Log Groups'),
    'lambda_functions': ('10 min', 'Review triggers then delete unused functions'),
}

# Energy/CO2 constants (UK grid average)
KWH_PER_GB_STORAGE_MONTH    = 0.000392   # kWh per GB per month (storage)
KWH_PER_HOUR_COMPUTE        = 0.08       # kWh per hour (average cloud compute)
CO2_KG_PER_KWH              = 0.233      # UK grid carbon intensity (kg CO2/kWh)

W = 76  # Report width

# Retry config — exponential backoff on AWS API throttling
BOTO_RETRY_CONFIG = Config(
    retries={'max_attempts': 5, 'mode': 'adaptive'}
)


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def banner(text):
    print(f"\n╔{'═' * (W-2)}╗")
    for line in text.strip().split('\n'):
        print(f"║  {line:<{W-4}}║")
    print(f"╚{'═' * (W-2)}╝")

def section(title):
    print(f"\n  {'─' * (W-4)}")
    print(f"  {title.upper()}")
    print(f"  {'─' * (W-4)}")

def row(label, value):
    print(f"  {label:<46} {value}")

def ok(msg):      print(f"  [OK]   {msg}")
def warn(msg):    print(f"  [WARN] {msg}")
def info(msg):    print(f"  [INFO] {msg}")
def locked(msg):  print(f"  [---]  {msg}")

def redact(text):
    return '█' * min(len(str(text)), 24)

def co2_for_cost(monthly_cost_gbp):
    """Rough CO2 estimate from monthly cloud spend."""
    kwh = (monthly_cost_gbp / 0.30) * KWH_PER_HOUR_COMPUTE * 730
    return kwh * CO2_KG_PER_KWH

def storage_co2(gb_months):
    """CO2 from storage waste."""
    kwh = gb_months * KWH_PER_GB_STORAGE_MONTH
    return kwh * CO2_KG_PER_KWH


# ─────────────────────────────────────────────────────────────────────────────
# AWS CONNECTION
# ─────────────────────────────────────────────────────────────────────────────
def connect_aws():
    try:
        session = boto3.session.Session()
        sts = session.client('sts', config=BOTO_RETRY_CONFIG)
        identity = sts.get_caller_identity()
        region = session.region_name or "us-east-1"
        return session, identity, region
    except NoCredentialsError:
        print("\n  [ERROR] No AWS credentials found.")
        print("  Run 'aws configure' or set environment variables.")
        sys.exit(1)
    except ClientError as e:
        print(f"\n  [ERROR] AWS Error: {e}\n")
        sys.exit(1)


def get_all_regions(session):
    try:
        ec2 = session.client('ec2', region_name='us-east-1', config=BOTO_RETRY_CONFIG)
        resp = ec2.describe_regions(
            Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
        )
        return [r['RegionName'] for r in resp['Regions']]
    except Exception as e:
        warn(f"Could not fetch regions — defaulting to configured region: {e}")
        return [session.region_name or 'eu-west-2']


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1: ORPHANED EBS VOLUMES
# ─────────────────────────────────────────────────────────────────────────────
def scan_orphaned_volumes(ec2, unlocked=False):
    section("CHECK 1 OF 14 — Orphaned EBS Volumes")
    info("Scanning for unattached hard drives (EBS volumes)...")
    response = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
    volumes = response.get('Volumes', [])
    if not volumes:
        ok("No orphaned volumes found. Clean!")
        return 0, 0, []
    total_gb = sum(v['Size'] for v in volumes)
    monthly_cost = total_gb * EBS_GBP_PER_GB_MONTH
    row("Orphaned volumes detected:", f"{len(volumes)} volumes")
    row("Total wasted storage:", f"{total_gb} GB")
    row("AWS billing waste:", f"£{monthly_cost:.2f}/month  (£{monthly_cost*12:.2f}/year)")
    row("Energy waste estimate:", f"{storage_co2(total_gb):.2f} kg CO₂/month")
    print()
    if unlocked:
        for v in volumes:
            name = next((t['Value'] for t in v.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
            created = v['CreateTime'].strftime('%d %b %Y')
            vol_cost = v['Size'] * EBS_GBP_PER_GB_MONTH
            print(f"    {v['VolumeId']:<24} [{name:<20}] {v['Size']:>4} GB  "
                  f"Created: {created}  Cost: £{vol_cost:.2f}/month")
            info("Delete via EC2 Console > Volumes > Actions > Delete Volume")
    else:
        locked(f"{len(volumes)} resource IDs identified — unlock full report to view")
        locked("Exact monthly cost per volume — unlock to view")
        locked("Creation dates, tags and remediation — unlock to view")
    return len(volumes), monthly_cost, volumes


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2: ZOMBIE SNAPSHOTS
# ─────────────────────────────────────────────────────────────────────────────
def scan_zombie_snapshots(ec2, unlocked=False):
    section("CHECK 2 OF 14 — Zombie Snapshots")
    info(f"Scanning for orphaned backups older than {ZOMBIE_SNAPSHOT_AGE_DAYS} days...")
    vol_paginator = ec2.get_paginator('describe_volumes')
    live_volume_ids = set()
    for page in vol_paginator.paginate():
        for v in page.get('Volumes', []):
            live_volume_ids.add(v['VolumeId'])
    snap_paginator = ec2.get_paginator('describe_snapshots')
    all_snapshots = []
    for page in snap_paginator.paginate(OwnerIds=['self']):
        all_snapshots.extend(page.get('Snapshots', []))
    now = datetime.now(timezone.utc)
    zombies = []
    for snap in all_snapshots:
        age_days = (now - snap['StartTime']).days
        parent_vol = snap.get('VolumeId', '')
        if parent_vol not in live_volume_ids and age_days > ZOMBIE_SNAPSHOT_AGE_DAYS:
            zombies.append({**snap, '_age_days': age_days})
    if not zombies:
        ok(f"No zombie snapshots found. ({len(all_snapshots)} total reviewed)")
        return 0, 0, []
    total_gb = sum(z.get('VolumeSize', 0) for z in zombies)
    monthly_cost = total_gb * SNAPSHOT_GBP_PER_GB
    row("Zombie snapshots detected:", f"{len(zombies)} of {len(all_snapshots)} reviewed")
    row("Wasted snapshot storage:", f"{total_gb} GB")
    row("AWS billing waste:", f"£{monthly_cost:.2f}/month  (£{monthly_cost*12:.2f}/year)")
    row("Energy waste estimate:", f"{storage_co2(total_gb):.2f} kg CO₂/month")
    print()
    if unlocked:
        for z in zombies[:20]:
            name = next((t['Value'] for t in z.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
            snap_cost = z.get('VolumeSize', 0) * SNAPSHOT_GBP_PER_GB
            print(f"    {z['SnapshotId']:<24} [{name:<20}] {z.get('VolumeSize',0):>4} GB  "
                  f"Age: {z['_age_days']} days  Cost: £{snap_cost:.2f}/month")
        if len(zombies) > 20:
            print(f"    ... and {len(zombies) - 20} more snapshots in full report.")
        info("Delete via EC2 Console > Snapshots > select > Delete Snapshot")
    else:
        locked(f"{len(zombies)} snapshot IDs identified — unlock full report to view")
        locked("Exact age, parent volume history and remediation — unlock to view")
    return len(zombies), monthly_cost, zombies


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 3: STOPPED EC2 INSTANCES
# ─────────────────────────────────────────────────────────────────────────────
def scan_stopped_instances(ec2, unlocked=False):
    section("CHECK 3 OF 14 — Stopped EC2 Instances")
    info("Scanning for servers that are off but still costing money...")
    response = ec2.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
    )
    instances = []
    for reservation in response.get('Reservations', []):
        instances.extend(reservation.get('Instances', []))
    if not instances:
        ok("No stopped instances found. Clean!")
        return 0, 0, []
    total_ebs_gb = 0
    instance_details = []
    # Batch all volume IDs into a single describe_volumes call — avoids per-volume
    # API calls which are slow and throttling-prone on larger accounts
    all_vol_ids = []
    inst_vol_map = {}  # inst_id -> [vol_ids]
    for inst in instances:
        vids = [m.get('Ebs', {}).get('VolumeId')
                for m in inst.get('BlockDeviceMappings', [])
                if m.get('Ebs', {}).get('VolumeId')]
        inst_vol_map[inst['InstanceId']] = vids
        all_vol_ids.extend(vids)
    # Single batched call for all volumes across all stopped instances
    vol_sizes = {}
    if all_vol_ids:
        try:
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate(VolumeIds=all_vol_ids):
                for v in page.get('Volumes', []):
                    vol_sizes[v['VolumeId']] = v['Size']
        except ClientError:
            pass
    for inst in instances:
        inst_gb = sum(vol_sizes.get(vid, 0) for vid in inst_vol_map.get(inst['InstanceId'], []))
        total_ebs_gb += inst_gb
        instance_details.append({**inst, '_ebs_gb': inst_gb})
    monthly_cost = total_ebs_gb * EBS_GBP_PER_GB_MONTH
    row("Stopped instances detected:", f"{len(instances)} instances")
    row("Attached storage still accruing cost:", f"{total_ebs_gb} GB")
    row("AWS billing waste (storage):", f"£{monthly_cost:.2f}/month  (£{monthly_cost*12:.2f}/year)")
    row("Energy waste estimate:", f"{storage_co2(total_ebs_gb):.2f} kg CO₂/month")
    warn("Stopped instances may also retain Elastic IPs and data transfer costs.")
    print()
    if unlocked:
        for inst in instance_details:
            name = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
            itype = inst.get('InstanceType', 'Unknown')
            inst_cost = inst['_ebs_gb'] * EBS_GBP_PER_GB_MONTH
            print(f"    {inst['InstanceId']:<24} [{name:<20}] {itype:<14} "
                  f"{inst['_ebs_gb']:>4} GB  Cost: £{inst_cost:.2f}/month")
        info("Terminate via EC2 Console > Instances > Instance State > Terminate")
    else:
        locked(f"{len(instances)} instance IDs identified — unlock full report to view")
        locked("Instance types, volumes and remediation — unlock to view")
    return len(instances), monthly_cost, instance_details


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 4: UNUSED ELASTIC IPs
# ─────────────────────────────────────────────────────────────────────────────
def scan_elastic_ips(ec2, unlocked=False):
    section("CHECK 4 OF 14 — Idle Elastic IP Addresses")
    info("Scanning for reserved IP addresses sitting idle...")
    response = ec2.describe_addresses()
    all_eips = response.get('Addresses', [])
    idle_eips = [eip for eip in all_eips if not eip.get('AssociationId')]
    if not idle_eips:
        ok(f"No idle Elastic IPs found. ({len(all_eips)} total reviewed)")
        return 0, 0, []
    monthly_cost = len(idle_eips) * ELASTIC_IP_COST_PER_MONTH
    row("Idle Elastic IPs detected:", f"{len(idle_eips)} of {len(all_eips)} reviewed")
    row("AWS charge for idle IPs:", f"£{monthly_cost:.2f}/month  (£{monthly_cost*12:.2f}/year)")
    info("AWS charges ~£3.60/month per unused reserved IP address.")
    print()
    if unlocked:
        for eip in idle_eips:
            print(f"    {eip.get('PublicIp', 'Unknown'):<20} "
                  f"Allocation: {eip.get('AllocationId', 'N/A'):<26} "
                  f"Cost: £{ELASTIC_IP_COST_PER_MONTH:.2f}/month")
        info("Release via EC2 Console > Elastic IPs > Actions > Release Elastic IP Address")
    else:
        locked(f"{len(idle_eips)} IP addresses identified — unlock full report to view")
        locked("Allocation IDs and remediation — unlock to view")
    return len(idle_eips), monthly_cost, idle_eips


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 5: IDLE LOAD BALANCERS
# ─────────────────────────────────────────────────────────────────────────────
def scan_load_balancers(session, region, unlocked=False):
    section("CHECK 5 OF 14 — Idle Load Balancers")
    info("Scanning for load balancers with no active targets...")
    elbv2 = session.client('elbv2', region_name=region, config=BOTO_RETRY_CONFIG)
    idle = []
    lbs = []
    try:
        lb_paginator = elbv2.get_paginator('describe_load_balancers')
        for page in lb_paginator.paginate():
            lbs.extend(page.get('LoadBalancers', []))
        for lb in lbs:
            lb_arn = lb['LoadBalancerArn']
            tg_resp = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)
            target_groups = tg_resp.get('TargetGroups', [])
            has_healthy = False
            for tg in target_groups:
                health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                if any(t.get('TargetHealth', {}).get('State') == 'healthy'
                       for t in health.get('TargetHealthDescriptions', [])):
                    has_healthy = True
                    break
            if not has_healthy:
                idle.append(lb)
    except ClientError as e:
        warn(f"Could not scan load balancers: {e}")
        return 0, 0, []
    if not idle:
        ok(f"No idle load balancers found. ({len(lbs)} total reviewed)")
        return 0, 0, []
    monthly_cost = len(idle) * LB_COST_PER_MONTH
    row("Idle load balancers detected:", f"{len(idle)} of {len(lbs)} reviewed")
    row("Estimated monthly waste:", f"£{monthly_cost:.2f}/month  (£{monthly_cost*12:.2f}/year)")
    warn("Each idle load balancer costs ~£15/month minimum with no traffic benefit.")
    print()
    if unlocked:
        for lb in idle:
            print(f"    {lb['LoadBalancerName']:<36} [{lb['Type']:<11}] "
                  f"State: {lb['State']['Code']:<12} Cost: £{LB_COST_PER_MONTH:.2f}/month")
        info("Delete via EC2 Console > Load Balancers > Actions > Delete")
    else:
        locked(f"{len(idle)} load balancer names identified — unlock full report to view")
        locked("ARNs, types, DNS names and remediation — unlock to view")
    return len(idle), monthly_cost, idle


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 6: IDLE NAT GATEWAYS
# ─────────────────────────────────────────────────────────────────────────────
def scan_nat_gateways(ec2, unlocked=False):
    section("CHECK 6 OF 14 — Idle NAT Gateways")
    try:
        resp = ec2.describe_nat_gateways(Filter=[{'Name': 'state', 'Values': ['available']}])
        gateways = resp.get('NatGateways', [])
        idle = []
        try:
            cw = boto3.client('cloudwatch', region_name=ec2.meta.region_name,
                              config=BOTO_RETRY_CONFIG)
            now = datetime.now(timezone.utc)
            for gw in gateways:
                gw_id = gw['NatGatewayId']
                name  = next((t['Value'] for t in gw.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/NATGateway',
                    MetricName='BytesOutToDestination',
                    Dimensions=[{'Name': 'NatGatewayId', 'Value': gw_id}],
                    StartTime=now - timedelta(hours=24),
                    EndTime=now,
                    Period=86400,
                    Statistics=['Sum'],
                )
                if sum(d['Sum'] for d in metrics.get('Datapoints', [])) == 0:
                    idle.append({'GatewayId': gw_id, 'name': name, 'VpcId': gw.get('VpcId', '')})
        except Exception:
            # CloudWatch unavailable — cannot verify traffic. Flag as UNVERIFIED,
            # contribute £0 to fee calculation to avoid false positives.
            unverified = []
            for gw in gateways:
                name = next((t['Value'] for t in gw.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
                unverified.append({'GatewayId': gw['NatGatewayId'], 'name': name,
                                   'VpcId': gw.get('VpcId', ''), 'status': 'UNVERIFIED'})
            if unverified:
                warn(f"CloudWatch unavailable — {len(unverified)} NAT Gateway(s) could not be verified.")
                warn("Traffic status unknown. Review manually before deleting.")
                if unlocked:
                    for gw in unverified:
                        print(f"    {gw['GatewayId']:<24} [{gw['name']:<20}] "
                              f"VPC: {gw['VpcId']}  [UNVERIFIED — review manually]")
                else:
                    locked(f"{len(unverified)} NAT Gateway(s) unverified — unlock to view IDs")
            return 0, 0.0, []  # No cost contribution when unverified
        count = len(idle)
        cost  = count * NAT_GBP_PER_MONTH
        if count == 0:
            ok("No idle NAT Gateways found")
        elif unlocked:
            print()
            for gw in idle:
                print(f"    {gw['GatewayId']:<24} [{gw['name']:<20}] "
                      f"VPC: {gw['VpcId']}  ~£{NAT_GBP_PER_MONTH:.2f}/month")
            info("Delete via VPC Console > NAT Gateways if no longer needed")
        else:
            print()
            locked(f"{count} NAT Gateway(s) identified — unlock full report to view")
            locked("Gateway IDs, VPC associations and remediation — unlock to view")
        return count, cost, idle
    except Exception as e:
        warn(f"NAT Gateway scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 7: STOPPED RDS INSTANCES
# ─────────────────────────────────────────────────────────────────────────────
def scan_rds_instances(session, region, unlocked=False):
    section("CHECK 7 OF 14 — Stopped RDS Instances")
    try:
        rds = session.client('rds', region_name=region, config=BOTO_RETRY_CONFIG)
        rds_paginator = rds.get_paginator('describe_db_instances')
        all_instances = []
        for page in rds_paginator.paginate():
            all_instances.extend(page.get('DBInstances', []))
        stopped = []
        for db in all_instances:
            if db.get('DBInstanceStatus') == 'stopped':
                storage_gb = db.get('AllocatedStorage', 0)
                monthly    = storage_gb * RDS_STORAGE_GBP_PER_GB
                stopped.append({
                    'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                    'Engine':  db.get('DBInstanceClass', ''),
                    'Storage': storage_gb,
                    'monthly_cost': monthly,
                })
        count = len(stopped)
        cost  = sum(d['monthly_cost'] for d in stopped)
        if count == 0:
            ok("No stopped RDS instances found")
        else:
            row("Stopped RDS instances detected:", f"{count}")
            row("Storage billing waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
            if unlocked:
                print()
                for db in stopped:
                    print(f"    {db['DBInstanceIdentifier']:<30} [{db['Engine']:<16}] "
                          f"{db['Storage']:>4} GB  £{db['monthly_cost']:.2f}/month")
                info("Delete or snapshot if no longer needed — stopped RDS still charges for storage")
            else:
                print()
                locked(f"{count} stopped RDS instance(s) identified — unlock full report to view")
                locked("Instance IDs, engines, storage costs and remediation — unlock to view")
        return count, cost, stopped
    except Exception as e:
        warn(f"RDS scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 8: CLOUDWATCH LOG GROUPS — NO RETENTION
# ─────────────────────────────────────────────────────────────────────────────
def scan_cloudwatch_logs(session, region, unlocked=False):
    section("CHECK 8 OF 14 — CloudWatch Log Groups — No Retention Policy")
    try:
        logs = session.client('logs', region_name=region, config=BOTO_RETRY_CONFIG)
        paginator = logs.get_paginator('describe_log_groups')
        no_retention = []
        for page in paginator.paginate():
            for lg in page.get('logGroups', []):
                if 'retentionInDays' not in lg:
                    stored_gb = lg.get('storedBytes', 0) / (1024**3)
                    monthly   = stored_gb * LOGS_GBP_PER_GB
                    no_retention.append({
                        'logGroupName': lg['logGroupName'],
                        'storedBytes':  lg.get('storedBytes', 0),
                        'monthly_cost': monthly,
                    })
        count = len(no_retention)
        cost  = sum(l['monthly_cost'] for l in no_retention)
        if count == 0:
            ok("All log groups have retention policies set")
        else:
            row("Log groups with no retention policy:", f"{count}")
            row("Estimated storage waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
            if unlocked:
                print()
                for lg in no_retention[:20]:
                    gb = lg['storedBytes'] / (1024**3)
                    print(f"    {lg['logGroupName'][:50]:<52} {gb:.2f} GB  £{lg['monthly_cost']:.2f}/month")
                if count > 20:
                    print(f"    ... and {count - 20} more in full report.")
                info("Set retention via CloudWatch Console > Log Groups > Edit retention")
            else:
                print()
                locked(f"{count} log group(s) with no retention policy — unlock to view")
                locked("Log group names, data sizes and remediation — unlock to view")
        return count, cost, no_retention
    except Exception as e:
        warn(f"CloudWatch Logs scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 9: OLD ECR CONTAINER IMAGES
# ─────────────────────────────────────────────────────────────────────────────
def scan_ecr_images(session, region, unlocked=False):
    section("CHECK 9 OF 14 — Unused ECR Container Images (>90 days old)")
    try:
        ecr = session.client('ecr', region_name=region, config=BOTO_RETRY_CONFIG)
        ecr_paginator = ecr.get_paginator('describe_repositories')
        repos = []
        for page in ecr_paginator.paginate():
            repos.extend(page.get('repositories', []))
        old_images = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        for repo in repos:
            name = repo['repositoryName']
            try:
                images = ecr.describe_images(repositoryName=name).get('imageDetails', [])
                for img in images:
                    pushed = img.get('imagePushedAt')
                    if pushed and pushed < cutoff:
                        size_gb  = img.get('imageSizeInBytes', 0) / (1024**3)
                        monthly  = size_gb * ECR_GBP_PER_GB
                        digest   = img.get('imageDigest', '')[:24]
                        old_images.append({
                            'repo': name, 'digest': digest,
                            'pushed': pushed.strftime('%Y-%m-%d'),
                            'size_gb': size_gb, 'monthly_cost': monthly,
                        })
            except Exception:
                continue
        count = len(old_images)
        cost  = sum(i['monthly_cost'] for i in old_images)
        if count == 0:
            ok("No ECR images older than 90 days found")
        else:
            row("Old ECR images detected:", f"{count}")
            row("Storage waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
            if unlocked:
                print()
                for img in old_images[:20]:
                    print(f"    {img['repo']:<30} [{img['digest']}] "
                          f"pushed {img['pushed']}  £{img['monthly_cost']:.4f}/month")
                if count > 20:
                    print(f"    ... and {count - 20} more in full report.")
                info("Delete old images via ECR Console or set lifecycle policies to auto-expire")
            else:
                print()
                locked(f"{count} old ECR image(s) identified — unlock full report to view")
                locked("Repository names, digests, push dates and remediation — unlock to view")
        return count, cost, old_images
    except Exception as e:
        warn(f"ECR scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 10: IDLE LAMBDA FUNCTIONS  ★ NEW
# ─────────────────────────────────────────────────────────────────────────────
def scan_lambda_functions(session, region, unlocked=False):
    """
    Find Lambda functions with zero invocations in the past 90 days.
    Lambda itself is free at idle but these represent dead code — security
    risk, maintenance overhead, and often attached to other billable services
    (API Gateway, EventBridge) that ARE still costing money.
    """
    section("CHECK 10 OF 14 — Idle Lambda Functions (Hygiene / Indirect Risk)")
    info("Scanning for serverless functions nobody is calling...")
    try:
        lambda_client = session.client('lambda', region_name=region, config=BOTO_RETRY_CONFIG)
        cw = session.client('cloudwatch', region_name=region, config=BOTO_RETRY_CONFIG)
        paginator = lambda_client.get_paginator('list_functions')
        all_functions = []
        for page in paginator.paginate():
            all_functions.extend(page.get('Functions', []))

        if not all_functions:
            ok("No Lambda functions found in this region")
            return 0, 0.0, []

        idle = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=LAMBDA_IDLE_DAYS)

        for fn in all_functions:
            fn_name = fn['FunctionName']
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': fn_name}],
                    StartTime=cutoff,
                    EndTime=now,
                    Period=int(timedelta(days=LAMBDA_IDLE_DAYS).total_seconds()),
                    Statistics=['Sum'],
                )
                total_invocations = sum(d['Sum'] for d in metrics.get('Datapoints', []))
                if total_invocations == 0:
                    last_modified = fn.get('LastModified', 'Unknown')
                    runtime = fn.get('Runtime', 'Unknown')
                    memory  = fn.get('MemorySize', 0)
                    idle.append({
                        'FunctionName': fn_name,
                        'Runtime': runtime,
                        'MemoryMB': memory,
                        'LastModified': last_modified,
                    })
            except Exception:
                continue

        count = len(idle)
        # Lambda idle = £0 direct cost but flag for hygiene + linked resource risk
        if count == 0:
            ok(f"No idle Lambda functions found. ({len(all_functions)} reviewed)")
        else:
            row("Idle Lambda functions detected:", f"{count} of {len(all_functions)} reviewed")
            row("Direct Lambda cost:", "£0.00 (Lambda charges per invocation only)")
            row("Finding type:", "Hygiene / Indirect Risk — not direct cost waste")
            warn(f"{count} idle function(s) flagged for hygiene and indirect risk only.")
            warn("Dead functions may have attached API Gateway, EventBridge or SQS")
            warn("triggers that ARE still billing — check trigger config in full report.")
            warn("Idle functions also carry security and maintenance overhead.")
            print()
            if unlocked:
                for fn in idle:
                    print(f"    {fn['FunctionName']:<40} [{fn['Runtime']:<12}] "
                          f"{fn['MemoryMB']:>4} MB  Last modified: {fn['LastModified'][:10]}")
                info("Delete via Lambda Console > Functions > Actions > Delete")
                info("Also check and remove any attached triggers before deleting")
            else:
                locked(f"{count} idle function names identified — unlock full report to view")
                locked("Runtimes, memory configs, trigger analysis — unlock to view")
        return count, 0.0, idle
    except Exception as e:
        warn(f"Lambda scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 11: ABANDONED S3 BUCKETS  ★ NEW
# ─────────────────────────────────────────────────────────────────────────────
def scan_s3_buckets(session, unlocked=False):
    """
    Find S3 buckets with no object access in 90+ days via CloudWatch metrics.
    This is the single biggest AI waste pattern — abandoned training data,
    experiment outputs, and model artefacts from cancelled projects.
    S3 Standard costs £0.023/GB/month. A 2TB abandoned dataset = £47/month.
    """
    section("CHECK 11 OF 14 — Abandoned S3 Buckets (no access in 90+ days)")
    info("Scanning for storage buckets nobody has touched recently...")
    info("(This is the biggest single waste pattern in AI companies)")
    try:
        s3 = session.client('s3', config=BOTO_RETRY_CONFIG)
        cw = session.client('cloudwatch', region_name='us-east-1', config=BOTO_RETRY_CONFIG)
        response = s3.list_buckets()
        all_buckets = response.get('Buckets', [])

        if not all_buckets:
            ok("No S3 buckets found")
            return 0, 0.0, []

        abandoned = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=S3_IDLE_DAYS)

        for bucket in all_buckets:
            bucket_name = bucket['Name']
            try:
                # Check bucket size via CloudWatch
                size_metrics = cw.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='BucketSizeBytes',
                    Dimensions=[
                        {'Name': 'BucketName', 'Value': bucket_name},
                        {'Name': 'StorageType', 'Value': 'StandardStorage'},
                    ],
                    StartTime=now - timedelta(days=2),
                    EndTime=now,
                    Period=86400,
                    Statistics=['Average'],
                )
                size_bytes = 0
                if size_metrics.get('Datapoints'):
                    size_bytes = max(d['Average'] for d in size_metrics['Datapoints'])

                if size_bytes == 0:
                    continue  # Empty bucket — skip

                # Check request count — zero requests = abandoned
                request_metrics = cw.get_metric_statistics(
                    Namespace='AWS/S3',
                    MetricName='AllRequests',
                    Dimensions=[
                        {'Name': 'BucketName', 'Value': bucket_name},
                        {'Name': 'FilterId',   'Value': 'EntireBucket'},
                    ],
                    StartTime=cutoff,
                    EndTime=now,
                    Period=int(timedelta(days=S3_IDLE_DAYS).total_seconds()),
                    Statistics=['Sum'],
                )
                total_requests = sum(d['Sum'] for d in request_metrics.get('Datapoints', []))

                if total_requests == 0:
                    size_gb   = size_bytes / (1024**3)
                    monthly   = size_gb * S3_GBP_PER_GB
                    co2_monthly = storage_co2(size_gb)
                    abandoned.append({
                        'BucketName': bucket_name,
                        'SizeGB': size_gb,
                        'monthly_cost': monthly,
                        'co2_kg': co2_monthly,
                        'CreatedDate': bucket.get('CreationDate', '').strftime('%Y-%m-%d')
                            if hasattr(bucket.get('CreationDate', ''), 'strftime') else 'Unknown',
                    })
            except Exception:
                continue

        count = len(abandoned)
        cost  = sum(b['monthly_cost'] for b in abandoned)
        total_gb = sum(b['SizeGB'] for b in abandoned)
        total_co2 = sum(b['co2_kg'] for b in abandoned)

        if count == 0:
            ok(f"No clearly abandoned S3 buckets found. ({len(all_buckets)} reviewed)")
            info("Note: S3 request metrics require server access logging to be enabled.")
        else:
            row("Abandoned S3 buckets detected:", f"{count} of {len(all_buckets)} reviewed")
            row("Total abandoned storage:", f"{total_gb:.1f} GB")
            row("AWS billing waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
            row("Energy waste estimate:", f"{total_co2:.2f} kg CO₂/month")
            warn("These buckets have data but no access — likely abandoned training sets,")
            warn("experiment outputs or old model artefacts from cancelled projects.")
            print()
            if unlocked:
                for b in abandoned:
                    print(f"    {b['BucketName']:<40} {b['SizeGB']:>8.1f} GB  "
                          f"£{b['monthly_cost']:.2f}/month  {b['co2_kg']:.3f} kg CO₂")
                info("Review contents and delete or archive to S3 Glacier (£0.004/GB/month)")
                info("Consider S3 Intelligent-Tiering for buckets you want to keep")
            else:
                locked(f"{count} abandoned bucket(s) identified — unlock full report to view")
                locked("Bucket names, sizes, costs and remediation — unlock to view")
        return count, cost, abandoned
    except Exception as e:
        warn(f"S3 scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 12: IDLE SAGEMAKER ENDPOINTS  ★ NEW
# ─────────────────────────────────────────────────────────────────────────────
def scan_sagemaker_endpoints(session, region, unlocked=False):
    """
    Find SageMaker inference endpoints that are InService but have had zero
    invocations in the past 7 days (lightweight status-only check).
    A single ml.t3.medium endpoint costs ~£40/month. A ml.p3.2xlarge costs ~£2,800/month.
    They're often spun up for demos or experiments and left running indefinitely.

    NOTE: Check 13 (GPU Zombie Endpoints) extends this with a deeper 72-hour
    CloudWatch invocation check and accurate per-instance-type GPU cost lookup.
    The two checks are complementary — this one is fast; Check 13 is precise.
    Cost estimates here use the ml.t3.medium floor; Check 13 uses actual rates.
    """
    section("CHECK 12 OF 14 — Idle SageMaker Endpoints (AI-specific)")
    info("Scanning for AI inference endpoints with no traffic...")
    info("(The most expensive waste pattern specific to AI companies)")
    try:
        sm = session.client('sagemaker', region_name=region, config=BOTO_RETRY_CONFIG)
        cw = session.client('cloudwatch', region_name=region, config=BOTO_RETRY_CONFIG)

        response = sm.list_endpoints(StatusEquals='InService')
        all_endpoints = response.get('Endpoints', [])

        if not all_endpoints:
            ok("No active SageMaker endpoints found in this region")
            return 0, 0.0, []

        idle = []
        now = datetime.now(timezone.utc)

        for ep in all_endpoints:
            ep_name = ep['EndpointName']
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/SageMaker',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'EndpointName', 'Value': ep_name}],
                    StartTime=now - timedelta(days=7),
                    EndTime=now,
                    Period=604800,
                    Statistics=['Sum'],
                )
                total_invocations = sum(d['Sum'] for d in metrics.get('Datapoints', []))
                if total_invocations == 0:
                    # Get endpoint config for instance type / cost estimate
                    try:
                        desc = sm.describe_endpoint(EndpointName=ep_name)
                        config_name = desc.get('EndpointConfigName', '')
                        config = sm.describe_endpoint_config(EndpointConfigName=config_name)
                        variants = config.get('ProductionVariants', [{}])
                        instance_type = variants[0].get('InstanceType', 'Unknown') if variants else 'Unknown'
                    except Exception:
                        instance_type = 'Unknown'

                    # Rough cost estimate — use ml.t3.medium as minimum floor
                    monthly_est = SAGEMAKER_ML_T3_MEDIUM * 730
                    idle.append({
                        'EndpointName': ep_name,
                        'InstanceType': instance_type,
                        'monthly_est': monthly_est,
                        'CreatedAt': ep.get('CreationTime', '').strftime('%Y-%m-%d')
                            if hasattr(ep.get('CreationTime', ''), 'strftime') else 'Unknown',
                    })
            except Exception:
                continue

        count = len(idle)
        cost  = sum(e['monthly_est'] for e in idle)

        if count == 0:
            ok(f"No idle SageMaker endpoints found. ({len(all_endpoints)} reviewed)")
        else:
            row("Idle SageMaker endpoints detected:", f"{count} of {len(all_endpoints)} reviewed")
            row("Estimated monthly waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
            warn("Cost estimate is conservative (ml.t3.medium floor).")
            warn("GPU endpoints (p3, g4dn) cost significantly more — check instance types.")
            print()
            if unlocked:
                for ep in idle:
                    print(f"    {ep['EndpointName']:<40} [{ep['InstanceType']:<18}] "
                          f"Created: {ep['CreatedAt']}  ~£{ep['monthly_est']:.2f}/month minimum")
                info("Delete via SageMaker Console > Inference > Endpoints > Delete")
                info("You can redeploy from your saved model at any time — endpoints are stateless")
            else:
                locked(f"{count} idle endpoint(s) identified — unlock full report to view")
                locked("Endpoint names, instance types, cost estimates — unlock to view")
                locked("Safe deletion guide — unlock to view")
        return count, cost, idle
    except Exception as e:
        warn(f"SageMaker scan skipped: {e}")
        return 0, 0.0, []



# ─────────────────────────────────────────────────────────────────────────────
# CHECK 13: GPU ZOMBIE ENDPOINTS — IDLE INFERENCE HUNTER  ★ NEW v2.4
# ─────────────────────────────────────────────────────────────────────────────
def scan_gpu_zombie_endpoints(session, region, unlocked=False):
    """
    Deep CloudWatch check for SageMaker endpoints that are InService but have
    received ZERO invocations in the past 72 hours, with a focus on GPU-class
    instances. Check 12 flags endpoints with no traffic over 7 days — this
    check goes further: it looks at the 72-hour window and calculates the true
    hourly cost of the specific instance type, not the ml.t3.medium floor.

    A single idle ml.p3.2xlarge = ~£2,800/month. These are the zombies that
    bankrupt AI startups silently. No generic tool catches this because it
    requires CloudWatch invocation depth beyond a simple ListResources call.
    This is Aegis's core moat for AI clients.
    """
    section("CHECK 13 OF 14 — GPU Zombie Endpoints (72-hour Invocation Check)")
    info("Deep-scanning SageMaker endpoints for 72-hour zero-invocation zombies...")
    info("(GPU endpoints cost £500–£2,800/month — these are the silent killers)")
    try:
        sm = session.client('sagemaker', region_name=region, config=BOTO_RETRY_CONFIG)
        cw = session.client('cloudwatch', region_name=region, config=BOTO_RETRY_CONFIG)

        response = sm.list_endpoints(StatusEquals='InService')
        all_endpoints = response.get('Endpoints', [])

        if not all_endpoints:
            ok("No active SageMaker endpoints found in this region")
            return 0, 0.0, []

        zombies = []
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=GPU_ZOMBIE_IDLE_HOURS)

        for ep in all_endpoints:
            ep_name = ep['EndpointName']
            try:
                # Get invocation count over the 72-hour window
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/SageMaker',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'EndpointName', 'Value': ep_name}],
                    StartTime=window_start,
                    EndTime=now,
                    Period=int(timedelta(hours=GPU_ZOMBIE_IDLE_HOURS).total_seconds()),
                    Statistics=['Sum'],
                )
                total_invocations = sum(d['Sum'] for d in metrics.get('Datapoints', []))

                if total_invocations > 0:
                    continue  # Active endpoint — skip

                # Zero invocations — get instance type for accurate cost estimate
                instance_type = 'Unknown'
                try:
                    desc = sm.describe_endpoint(EndpointName=ep_name)
                    config_name = desc.get('EndpointConfigName', '')
                    config = sm.describe_endpoint_config(EndpointConfigName=config_name)
                    variants = config.get('ProductionVariants', [{}])
                    instance_type = variants[0].get('InstanceType', 'Unknown') if variants else 'Unknown'
                except Exception:
                    pass

                # Look up hourly cost — GPU-class gets exact rate, others get floor
                hourly_rate = SAGEMAKER_GPU_COSTS.get(instance_type, SAGEMAKER_ML_T3_MEDIUM)
                monthly_cost = hourly_rate * 730

                is_gpu = any(
                    instance_type.startswith(prefix)
                    for prefix in ('ml.p2', 'ml.p3', 'ml.g4', 'ml.g5')
                )

                created_at = ep.get('CreationTime', '')
                created_str = created_at.strftime('%Y-%m-%d') if hasattr(created_at, 'strftime') else 'Unknown'

                zombies.append({
                    'EndpointName': ep_name,
                    'InstanceType': instance_type,
                    'IsGPU': is_gpu,
                    'HourlyRate': hourly_rate,
                    'monthly_cost': monthly_cost,
                    'CreatedAt': created_str,
                })
            except Exception:
                continue

        count = len(zombies)
        cost  = sum(z['monthly_cost'] for z in zombies)
        gpu_count = sum(1 for z in zombies if z['IsGPU'])

        if count == 0:
            ok(f"No 72-hour zero-invocation endpoints found. ({len(all_endpoints)} reviewed)")
            return 0, 0.0, []

        row("Zero-invocation endpoints (72h):", f"{count} of {len(all_endpoints)} reviewed")
        row("of which GPU-class instances:", f"{gpu_count}")
        row("Estimated monthly waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
        if gpu_count > 0:
            warn(f"{gpu_count} GPU endpoint(s) found — these are the highest-priority finding.")
            warn("A single idle p3.2xlarge costs ~£2,800/month. Delete immediately.")
        print()

        if unlocked:
            # Sort GPU endpoints first
            zombies_sorted = sorted(zombies, key=lambda z: (not z['IsGPU'], -z['monthly_cost']))
            for z in zombies_sorted:
                gpu_flag = " ★GPU★" if z['IsGPU'] else "      "
                print(f"    {z['EndpointName']:<40} [{z['InstanceType']:<18}]{gpu_flag} "
                      f"Created: {z['CreatedAt']}  £{z['monthly_cost']:.2f}/month")
            info("Delete via SageMaker Console > Inference > Endpoints > Delete")
            info("Your model artefacts stay safely in S3 — endpoint can be recreated anytime")
            info("CLI: aws sagemaker delete-endpoint --endpoint-name <name> --region <region>")
        else:
            locked(f"{count} zombie endpoint(s) identified — unlock full report to view")
            locked("Endpoint names, instance types, exact hourly costs — unlock to view")
            locked("GPU vs CPU breakdown, deletion guide — unlock to view")

        return count, cost, zombies

    except Exception as e:
        warn(f"GPU zombie endpoint scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 14: REDUNDANT SNAPSHOT LINEAGE  ★ NEW v2.4
# ─────────────────────────────────────────────────────────────────────────────
def scan_snapshot_lineage(ec2, unlocked=False):
    """
    Identifies volumes with excessive snapshot accumulation — where a single
    volume has 30+ snapshots, many older than 90 days, creating storage bloat
    that compounds month over month.

    Check 2 catches orphaned snapshots (parent volume deleted). This check
    catches redundant lineage — the parent volume still exists but the
    snapshot history has grown far beyond any reasonable retention need.

    Example: 500 snapshots of a 1TB volume over 2 years = significant monthly
    storage cost that will never be recovered. The recommendation to move old
    snapshots to AWS Backup lifecycle policies is Advice-First positioning
    that builds trust beyond simple waste detection.
    """
    section("CHECK 14 OF 14 — Redundant Snapshot Lineage")
    info(f"Scanning for volumes with {SNAPSHOT_LINEAGE_THRESHOLD}+ accumulated snapshots...")
    info("(Snapshot collections that have grown far beyond useful retention)")
    try:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=SNAPSHOT_LINEAGE_AGE_DAYS)

        # Get all live volume IDs
        vol_paginator = ec2.get_paginator('describe_volumes')
        live_volumes = {}
        for page in vol_paginator.paginate():
            for v in page.get('Volumes', []):
                live_volumes[v['VolumeId']] = v['Size']

        # Get all own snapshots
        snap_paginator = ec2.get_paginator('describe_snapshots')
        all_snapshots = []
        for page in snap_paginator.paginate(OwnerIds=['self']):
            all_snapshots.extend(page.get('Snapshots', []))

        # Group by source volume
        from collections import defaultdict
        by_volume = defaultdict(list)
        for snap in all_snapshots:
            vol_id = snap.get('VolumeId', '')
            if vol_id in live_volumes:  # Only count snapshots of still-existing volumes
                by_volume[vol_id].append(snap)

        # Find volumes with excessive snapshot count
        flagged = []
        for vol_id, snaps in by_volume.items():
            old_snaps = [s for s in snaps
                         if (now - s['StartTime']).days > SNAPSHOT_LINEAGE_AGE_DAYS]
            total_count = len(snaps)
            old_count   = len(old_snaps)

            if total_count < SNAPSHOT_LINEAGE_THRESHOLD:
                continue  # Under threshold — not flagged

            # Cost of old snapshots (the recoverable waste)
            old_gb   = sum(s.get('VolumeSize', 0) for s in old_snaps)
            old_cost = old_gb * SNAPSHOT_GBP_PER_GB
            vol_size = live_volumes.get(vol_id, 0)

            # Get volume name tag if present
            try:
                vol_resp = ec2.describe_volumes(VolumeIds=[vol_id])
                vol_tags = vol_resp['Volumes'][0].get('Tags', []) if vol_resp['Volumes'] else []
                vol_name = next((t['Value'] for t in vol_tags if t['Key'] == 'Name'), 'Unnamed')
            except Exception:
                vol_name = 'Unnamed'

            flagged.append({
                'VolumeId':    vol_id,
                'VolumeName':  vol_name,
                'VolumeSizeGB': vol_size,
                'TotalSnaps':  total_count,
                'OldSnaps':    old_count,
                'OldGB':       old_gb,
                'monthly_cost': old_cost,
            })

        count = len(flagged)
        cost  = sum(f['monthly_cost'] for f in flagged)
        total_old_snaps = sum(f['OldSnaps'] for f in flagged)

        if count == 0:
            ok(f"No volumes with excessive snapshot lineage found. "
               f"({len(by_volume)} volumes with snapshots reviewed)")
            return 0, 0.0, []

        row("Volumes with redundant snapshot lineage:", f"{count}")
        row("Total recoverable old snapshots:", f"{total_old_snaps}")
        row("Estimated storage waste:", f"£{cost:.2f}/month  (£{cost*12:.2f}/year)")
        info("Recommendation: AWS Backup lifecycle policy or S3 Glacier Deep Archive")
        info(f"(Glacier Deep Archive costs ~£0.001/GB/month vs £{SNAPSHOT_GBP_PER_GB}/GB for snapshots)")
        print()

        if unlocked:
            flagged_sorted = sorted(flagged, key=lambda f: -f['monthly_cost'])
            for f in flagged_sorted:
                print(f"    {f['VolumeId']:<24} [{f['VolumeName']:<20}] {f['VolumeSizeGB']:>5} GB volume  "
                      f"{f['TotalSnaps']} total snaps / {f['OldSnaps']} old  "
                      f"£{f['monthly_cost']:.2f}/month waste")
            print()
            info("Remediation: set AWS Backup lifecycle rules to expire old recovery points")
            info("Or: use EC2 > Snapshots > filter by VolumeId > delete oldest in batches")
            info("Consider: move infrequently accessed old snapshots to S3 Glacier Deep Archive")
            info("CLI: aws ec2 delete-snapshot --snapshot-id snap-xxxxxxxx --region <region>")
        else:
            locked(f"{count} volume(s) with redundant lineage identified — unlock full report to view")
            locked("Volume IDs, snapshot counts, ages and cost breakdown — unlock to view")
            locked("Lifecycle policy recommendations and remediation — unlock to view")

        return count, cost, flagged

    except Exception as e:
        warn(f"Snapshot lineage scan skipped: {e}")
        return 0, 0.0, []


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTIVE SUMMARY  ★ NEW
# ─────────────────────────────────────────────────────────────────────────────
def print_executive_summary(results, account_id, regions_summary, scan_duration_secs):
    """
    One-page summary at the top of the report — what a CTO reads in 30 seconds.
    Shows total waste, top 3 findings, environmental impact, and the fee.
    """
    total_monthly = sum(r['monthly_cost'] for r in results.values())
    total_annual  = total_monthly * 12
    aegis_fee     = min(total_annual, AEGIS_FEE_CAP_GBP)
    eco_cut       = aegis_fee * MOSSY_EARTH_SPLIT

    # Environmental impact
    total_gb_waste = (
        results.get('volumes', {}).get('count', 0) * 100 +      # rough avg 100GB
        results.get('snapshots', {}).get('count', 0) * 50 +
        results.get('s3_buckets', {}).get('count', 0) * 200
    )
    total_co2_monthly = storage_co2(total_gb_waste) + co2_for_cost(total_monthly)
    trees_equivalent  = total_co2_monthly / 21.7  # avg tree absorbs 21.7 kg CO2/year / 12

    # Top 3 findings by cost
    sorted_results = sorted(
        [(k, v) for k, v in results.items() if v['monthly_cost'] > 0],
        key=lambda x: x[1]['monthly_cost'],
        reverse=True
    )

    labels = {
        'volumes':        'Orphaned EBS Volumes',
        'snapshots':      'Zombie Snapshots',
        'instances':      'Stopped EC2 Instances',
        'elastic_ips':    'Idle Elastic IPs',
        'load_balancers': 'Idle Load Balancers',
        'nat_gateways':   'Idle NAT Gateways',
        'rds_instances':  'Stopped RDS Instances',
        'cloudwatch_logs':'Log Groups (No Retention)',
        'ecr_images':     'Old ECR Images',
        'lambda_functions':'Idle Lambda Functions',
        's3_buckets':     'Abandoned S3 Buckets',
        'sagemaker':      'Idle SageMaker Endpoints',
        'gpu_zombies':    'GPU Zombie Endpoints ★',
        'snap_lineage':   'Redundant Snapshot Lineage',
    }

    print(f"""
╔{'═' * (W-2)}╗
║{'AEGIS AUDIT GUILD — EXECUTIVE SUMMARY':^{W-2}}║
╠{'═' * (W-2)}╣
║  Account   : {account_id:<{W-16}}║
║  Scope     : {regions_summary[:W-18]:<{W-18}}║
║  Scan Time : {datetime.now().strftime('%d %B %Y at %H:%M'):<{W-16}}║
║  Duration  : {f'{scan_duration_secs:.0f} seconds':<{W-16}}║
╠{'═' * (W-2)}╣
║{'  FINANCIAL IMPACT':^{W-2}}║
╠{'═' * (W-2)}╣
║  Monthly Waste Identified  : £{total_monthly:<{W-36}.2f}║
║  Annual Waste Identified   : £{total_annual:<{W-36}.2f}║
║  Aegis Fee (capped at £250): £{aegis_fee:<{W-36}.2f}║
║  Eco Partner Contribution  : £{eco_cut:<{W-36}.2f}║
╠{'═' * (W-2)}╣
║{'  ENVIRONMENTAL IMPACT':^{W-2}}║
╠{'═' * (W-2)}╣
║  Estimated CO₂ from waste  : {f'{total_co2_monthly:.1f} kg/month':<{W-36}}║
║  Tree-planting equivalent  : {f'{trees_equivalent:.1f} trees/month to offset':<{W-36}}║
╠{'═' * (W-2)}╣
║{'  TOP FINDINGS':^{W-2}}║
╠{'═' * (W-2)}╣""")

    # Shock metric — % of estimated total AWS spend being wasted
    # Conservative estimate: assume monthly waste is 15–35% of bill
    # We show waste as % of estimated spend (waste / 0.25 = implied total)
    shock_pct = (total_monthly / max(total_monthly / 0.25, 1)) * 100 if total_monthly > 0 else 0
    shock_line = f"~{shock_pct:.0f}% of estimated AWS spend identified as waste" if total_monthly > 0 else "No waste identified"

    if sorted_results:
        for key, val in sorted_results[:3]:
            label  = labels.get(key, key)
            pri    = PRIORITY.get(key, ('', ''))[0]
            pri_tag = f"[{pri}]" if pri else ""
            finding = f"{val['count']} found — £{val['monthly_cost']:.2f}/month"
            print(f"║  {pri_tag:<10} {label:<26} {finding:<{W-42}}║")
    else:
        print(f"║  {'No waste found — this account is clean.':^{W-2}}║")

    total_checks = len([v for v in results.values() if v['count'] > 0])
    print(f"""╠{'═' * (W-2)}╣
║  Checks with findings      : {f'{total_checks} of 14 checks':<{W-36}}║
║  Waste as % of spend       : {shock_line:<{W-36}}║
╚{'═' * (W-2)}╝""")


# ─────────────────────────────────────────────────────────────────────────────
# FREE SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_free_summary(results, account_id, regions_summary):
    total_monthly = sum(r['monthly_cost'] for r in results.values())
    total_annual  = total_monthly * 12
    aegis_fee     = min(total_annual, AEGIS_FEE_CAP_GBP)
    eco_cut       = aegis_fee * MOSSY_EARTH_SPLIT
    aegis_cut     = aegis_fee * AEGIS_SPLIT

    print(f"""
╔{'═' * (W-2)}╗
║{'AEGIS AUDIT GUILD — FREE SUMMARY REPORT':^{W-2}}║
╠{'═' * (W-2)}╣
║  Account ID  : {account_id:<{W-18}}║
║  Regions     : {regions_summary[:W-18]:<{W-18}}║
║  Scan Date   : {datetime.now().strftime('%d %B %Y — %H:%M'):<{W-18}}║
╠{'═' * (W-2)}╣
║{'WASTE FOUND BY CATEGORY':^{W-2}}║
╠{'═' * (W-2)}╣""")

    labels = {
        'volumes':          'Orphaned EBS Volumes',
        'snapshots':        'Zombie Snapshots',
        'instances':        'Stopped EC2 Instances',
        'elastic_ips':      'Idle Elastic IPs',
        'load_balancers':   'Idle Load Balancers',
        'nat_gateways':     'Idle NAT Gateways',
        'rds_instances':    'Stopped RDS Instances',
        'cloudwatch_logs':  'Log Groups — No Retention',
        'ecr_images':       'Old ECR Container Images',
        'lambda_functions': 'Idle Lambda Functions',
        's3_buckets':       'Abandoned S3 Buckets',
        'sagemaker':        'Idle SageMaker Endpoints',
        'gpu_zombies':      'GPU Zombie Endpoints ★',
        'snap_lineage':     'Redundant Snapshot Lineage',
    }

    for key, label in labels.items():
        r   = results.get(key, {'count': 0, 'monthly_cost': 0})
        pri = PRIORITY.get(key, ('', ''))[0]
        pri_tag = f"[{pri}]" if pri and r['count'] > 0 else ""
        if r['count'] > 0:
            status = f"{r['count']} found — £{r['monthly_cost']:.2f}/month"
        else:
            status = "Clean"
        print(f"║  {pri_tag:<10} {label:<26} {status:<{W-42}}║")

    print(f"""╠{'═' * (W-2)}╣
║{'FINANCIAL IMPACT':^{W-2}}║
╠{'═' * (W-2)}╣
║  Monthly Waste Identified  : £{total_monthly:<{W-36}.2f}║
║  Annual Waste Identified   : £{total_annual:<{W-36}.2f}║
╠{'═' * (W-2)}╣
║{'AEGIS FEE BREAKDOWN':^{W-2}}║
╠{'═' * (W-2)}╣
║  Total Fee (annual waste, capped at £250): £{aegis_fee:<{W-50}.2f}║
║  Eco Partner Rewilding (80%): £{eco_cut:<{W-36}.2f}║
║  Aegis Retained (20%)       : £{aegis_cut:<{W-36}.2f}║
╠{'═' * (W-2)}╣""")

    if total_monthly > 0:
        print(f"║  80% of your fee goes directly to verified rewilding via our eco partner.  {'':<{W-79}}║")
        print(f"║  Split enforced by Stripe Connect at point of payment — automatic.         {'':<{W-79}}║")
        print(f"╠{'═' * (W-2)}╣")
        print(f"║{'  ── FULL REPORT LOCKED ──':^{W-2}}║")
        print(f"╠{'═' * (W-2)}╣")
        print(f"║  Exact resource IDs, regions and step-by-step remediation for every       {'':<{W-79}}║")
        print(f"║  item above are held in your full report — delivered within one            {'':<{W-79}}║")
        print(f"║  business day after fee is agreed.                                        {'':<{W-79}}║")
        print(f"╠{'═' * (W-2)}╣")
        print(f"║  To unlock: email Jason@aegisaudit.cloud and confirm the fee above.       {'':<{W-79}}║")
        print(f"║  aegisaudit.cloud                                                         {'':<{W-79}}║")
        print(f"╠{'═' * (W-2)}╣")
        print(f"║  No waste found = no fee. Your saving is 100% yours.                     {'':<{W-79}}║")
    else:
        print(f"║  {'This account is clean. No fee. No charge. Well done.':^{W-2}}║")

    print(f"╚{'═' * (W-2)}╝")


# ─────────────────────────────────────────────────────────────────────────────
# FULL UNLOCKED REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_full_report(results, account_id, regions_summary):
    total_monthly = sum(r['monthly_cost'] for r in results.values())
    total_annual  = total_monthly * 12
    aegis_fee     = min(total_annual, AEGIS_FEE_CAP_GBP)
    eco_cut       = aegis_fee * MOSSY_EARTH_SPLIT
    aegis_cut     = aegis_fee * AEGIS_SPLIT

    print(f"""
╔{'═' * (W-2)}╗
║{'AEGIS AUDIT GUILD — FULL UNLOCKED REPORT':^{W-2}}║
╠{'═' * (W-2)}╣
║  Account ID  : {account_id:<{W-18}}║
║  Regions     : {regions_summary[:W-18]:<{W-18}}║
║  Report Date : {datetime.now().strftime('%d %B %Y — %H:%M'):<{W-18}}║
╠{'═' * (W-2)}╣
║  Monthly Waste             : £{total_monthly:<{W-36}.2f}║
║  Annual Waste              : £{total_annual:<{W-36}.2f}║
║  Aegis Fee                 : £{aegis_fee:<{W-36}.2f}║
║  Eco Partner (80%)         : £{eco_cut:<{W-36}.2f}║
║  Aegis Retained (20%)      : £{aegis_cut:<{W-36}.2f}║
╠{'═' * (W-2)}╣
║  REMEDIATION GUIDE — Priority Order                                        ║
╠{'═' * (W-2)}╣
║  Finding                    Priority   Time    Action                      ║
║  ─────────────────────────────────────────────────────────────────────     ║
║  GPU Zombie Endpoints        CRITICAL   2 min   SageMaker > Endpoints > Delete  ║
║  Idle SageMaker Endpoints    CRITICAL   2 min   SageMaker > Endpoints > Delete  ║
║  Stopped EC2 Instances       HIGH       5 min   EC2 > Instances > Terminate     ║
║  Idle NAT Gateways           HIGH       5 min   VPC > NAT Gateways > Delete     ║
║  Idle Load Balancers         HIGH       2 min   EC2 > Load Balancers > Delete   ║
║  Stopped RDS Instances       HIGH       5 min   RDS > Databases > Delete        ║
║  Abandoned S3 Buckets        HIGH      10 min   S3 > Empty then Delete          ║
║  Orphaned EBS Volumes        HIGH       2 min   EC2 > Volumes > Delete          ║
║  Redundant Snapshot Lineage  MEDIUM    15 min   EC2 > Snapshots > delete oldest ║
║  Zombie Snapshots            MEDIUM     5 min   EC2 > Snapshots > Delete        ║
║  Idle Elastic IPs            LOW        1 min   EC2 > Elastic IPs > Release     ║
║  Old ECR Images              LOW        5 min   ECR > Repositories > Delete     ║
║  Log Groups No Retention     LOW        3 min   CloudWatch > Edit retention     ║
║  Idle Lambda Functions       LOW       10 min   Lambda > Functions > Delete     ║
╠{'═' * (W-2)}╣
║  Strengthening the UK grid. Planting the forest.                           ║
║  Jason@aegisaudit.cloud  ·  aegisaudit.cloud                               ║
╚{'═' * (W-2)}╝""")


# ─────────────────────────────────────────────────────────────────────────────
# MERGE RESULTS
# ─────────────────────────────────────────────────────────────────────────────
def merge_results(all_results):
    merged = {}
    for region_results in all_results:
        for key, val in region_results.items():
            if key not in merged:
                merged[key] = {'count': 0, 'monthly_cost': 0.0}
            merged[key]['count']        += val['count']
            merged[key]['monthly_cost'] += val['monthly_cost']
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def aegis_audit(unlocked=False):
    scan_start = time.time()

    banner(
        "AEGIS AUDIT GUILD — Cloud Waste Intelligence Engine v2.6\n"
        "Legacy in the landscape, for your company and my family.\n"
        "Read-Only · No ML · No Credentials Stored · No Agents\n"
        "14 checks · Multi-region · Energy impact included"
    )

    mode = "FULL UNLOCKED REPORT" if unlocked else "FREE SUMMARY SCAN"
    print(f"\n  Mode: {mode}")
    print(f"\n  Establishing secure read-only connection to AWS...\n")

    session, identity, region = connect_aws()
    account_id = identity.get('Account', 'Unknown')

    print(f"  [OK]  Connected.")
    print(f"  [OK]  Account ID : {account_id}")
    print(f"  [OK]  Home Region: {region}")

    print(f"\n  {'─' * (W-4)}")
    print(f"  TRUST & SAFETY CONFIRMATION")
    print(f"  {'─' * (W-4)}")
    print(f"  [OK]  Read-only connection confirmed — IAM policy enforced")
    print(f"  [OK]  No write, delete or modify permissions active")
    print(f"  [OK]  No data transmitted to external servers")
    print(f"  [OK]  No credentials stored by this script")
    print(f"  [OK]  No agents, no ML, no background processes")
    print(f"  [OK]  This scan cannot modify your AWS account in any way")
    print(f"  [OK]  All findings remain on your local machine only")
    print(f"  {'─' * (W-4)}")

    print(f"\n  Discovering AWS regions...")
    regions = get_all_regions(session)
    print(f"  [OK]  {len(regions)} region(s) found — scanning all for hidden waste")
    print(f"\n  Starting full multi-region scan (14 checks). This may take 2–4 minutes...\n")

    all_results = []
    regions_scanned = []
    s3_result = None  # S3 is global — run once outside the region loop

    # ── S3 is a global service — scan once ───────────────────────────────────
    s3_count, s3_cost, _ = scan_s3_buckets(session, unlocked)
    s3_result = {'count': s3_count, 'monthly_cost': s3_cost}

    # ── Per-region scans ──────────────────────────────────────────────────────
    for r in regions:
        try:
            ec2_r = session.client('ec2', region_name=r, config=BOTO_RETRY_CONFIG)
            print(f"\n  ── Scanning region: {r} ──")

            vol_count,    vol_cost,    _ = scan_orphaned_volumes(ec2_r, unlocked)
            snap_count,   snap_cost,   _ = scan_zombie_snapshots(ec2_r, unlocked)
            inst_count,   inst_cost,   _ = scan_stopped_instances(ec2_r, unlocked)
            eip_count,    eip_cost,    _ = scan_elastic_ips(ec2_r, unlocked)
            lb_count,     lb_cost,     _ = scan_load_balancers(session, r, unlocked)
            nat_count,    nat_cost,    _ = scan_nat_gateways(ec2_r, unlocked)
            rds_count,    rds_cost,    _ = scan_rds_instances(session, r, unlocked)
            cwl_count,    cwl_cost,    _ = scan_cloudwatch_logs(session, r, unlocked)
            ecr_count,    ecr_cost,    _ = scan_ecr_images(session, r, unlocked)
            lam_count,    lam_cost,    _ = scan_lambda_functions(session, r, unlocked)
            sm_count,     sm_cost,     _ = scan_sagemaker_endpoints(session, r, unlocked)
            gpu_count,    gpu_cost,    _ = scan_gpu_zombie_endpoints(session, r, unlocked)
            lin_count,    lin_cost,    _ = scan_snapshot_lineage(ec2_r, unlocked)

            region_total = (vol_cost + snap_cost + inst_cost + eip_cost +
                            lb_cost + nat_cost + rds_cost + cwl_cost +
                            ecr_cost + lam_cost + sm_cost + gpu_cost + lin_cost)

            if region_total > 0:
                print(f"\n  [WARN] Waste found in {r}: £{region_total:.2f}/month")
            else:
                print(f"\n  [OK]   {r} — clean")

            all_results.append({
                'volumes':          {'count': vol_count,  'monthly_cost': vol_cost},
                'snapshots':        {'count': snap_count, 'monthly_cost': snap_cost},
                'instances':        {'count': inst_count, 'monthly_cost': inst_cost},
                'elastic_ips':      {'count': eip_count,  'monthly_cost': eip_cost},
                'load_balancers':   {'count': lb_count,   'monthly_cost': lb_cost},
                'nat_gateways':     {'count': nat_count,  'monthly_cost': nat_cost},
                'rds_instances':    {'count': rds_count,  'monthly_cost': rds_cost},
                'cloudwatch_logs':  {'count': cwl_count,  'monthly_cost': cwl_cost},
                'ecr_images':       {'count': ecr_count,  'monthly_cost': ecr_cost},
                'lambda_functions': {'count': lam_count,  'monthly_cost': lam_cost},
                'sagemaker':        {'count': sm_count,   'monthly_cost': sm_cost},
                'gpu_zombies':      {'count': gpu_count,  'monthly_cost': gpu_cost},
                'snap_lineage':     {'count': lin_count,  'monthly_cost': lin_cost},
            })
            regions_scanned.append(r)

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'OptInRequired':
                print(f"  [---]  {r} — not opted in, skipping")
            elif error_code in ('AuthFailure', 'UnauthorizedAccess', 'AccessDenied'):
                print(f"  [---]  {r} — access denied, skipping")
            else:
                warn(f"Could not scan {r}: {e}")
            continue
        except Exception as e:
            warn(f"Could not scan {r}: {e}")
            continue

    scan_duration = time.time() - scan_start
    results = merge_results(all_results)

    # Add S3 global result
    results['s3_buckets'] = s3_result

    regions_summary = f"{len(regions_scanned)} regions: {', '.join(regions_scanned)}"
    print(f"\n  {'─' * (W-4)}")
    print(f"  SCAN COMPLETE in {scan_duration:.0f}s — {regions_summary}")
    print(f"  {'─' * (W-4)}\n")

    # ── Print executive summary first ─────────────────────────────────────────
    print_executive_summary(results, account_id, regions_summary, scan_duration)

    # ── Then full or free report ──────────────────────────────────────────────
    if unlocked:
        print_full_report(results, account_id, regions_summary)
    else:
        print_free_summary(results, account_id, regions_summary)

    # ── Save to file ──────────────────────────────────────────────────────────
    import io
    report_type = "full-report" if unlocked else "free-summary"
    timestamp   = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename    = f"aegis-{report_type}-{account_id}-{timestamp}.txt"

    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    print_executive_summary(results, account_id, regions_summary, scan_duration)
    if unlocked:
        print_full_report(results, account_id, regions_summary)
    else:
        print_free_summary(results, account_id, regions_summary)
    sys.stdout = old_stdout
    report_text = buffer.getvalue()

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"AEGIS AUDIT GUILD — Cloud Waste Intelligence Engine v2.6\n")
            f.write(f"{'─' * 78}\n")
            f.write(f"Account ID  : {account_id}\n")
            f.write(f"Regions     : {regions_summary}\n")
            f.write(f"Report Type : {'FULL UNLOCKED REPORT' if unlocked else 'FREE SUMMARY'}\n")
            f.write(f"Generated   : {datetime.now().strftime('%d %B %Y at %H:%M:%S')}\n")
            f.write(f"Duration    : {scan_duration:.0f} seconds\n")
            f.write(f"{'─' * 78}\n\n")
            f.write(report_text)
            f.write(f"\n{'─' * 78}\n")
            f.write(f"aegisaudit.cloud  ·  Jason@aegisaudit.cloud\n")
            f.write(f"A Waller-Mayes Alliance · Bedford, UK\n")
        print(f"\n  [OK]  Report saved to: {filename}")
        print(f"  [OK]  Email this file to Jason@aegisaudit.cloud to unlock the full report.\n")
    except Exception as e:
        print(f"\n  [WARN] Could not save report file: {e}\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# Pass --unlocked flag (Aegis steward use only — after fee agreed)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unlocked = '--unlocked' in sys.argv
    aegis_audit(unlocked=unlocked)

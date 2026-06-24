# IAM Security Scanner - Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for all security vulnerabilities detected by the IAM Security Scanner. Each vulnerability includes remediation steps using AWS Console, AWS CLI, and Python boto3 methods. Check IDs (A.1, B.2, ...) match [security-checks.md](security-checks.md); framework mappings are in [compliance.md](compliance.md).

> **Guiding principle**: prefer **temporary credentials** (IAM Identity Center / IAM roles) over long-lived users and access keys, and always grant **least privilege**.

> **Note on compliance tokens**: the `Compliance:` line on each finding lists indicative framework references for orientation. The authoritative, per-check control mappings are maintained in [compliance.md](compliance.md).

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| IAM Security Best Practices | [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) |
| Root User Best Practices | [Root User](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html) |
| Multi-Factor Authentication | [Using MFA in AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html) |
| Account Password Policy | [Setting a Password Policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html) |
| Access Key Rotation | [Rotating Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey) |
| Policy Least Privilege | [Least-Privilege Permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege) |
| IAM Access Analyzer | [What is IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html) |
| Cross-Account Confused Deputy | [Confused Deputy Problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html) |
| AWS CLI IAM Commands | [AWS CLI IAM Reference](https://docs.aws.amazon.com/cli/latest/reference/iam/) |
| Boto3 IAM Documentation | [Boto3 IAM Service](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html) |

## Table of Contents

1. [User & Credential Security](#user--credential-security)
2. [Password Policy](#password-policy)
3. [Managed Policy Security](#managed-policy-security)
4. [Role Security](#role-security)
5. [Group Security](#group-security)
6. [Account Settings](#account-settings)
7. [Privilege Escalation & Trust](#privilege-escalation--trust)
8. [Quick Reference Commands](#quick-reference-commands)
9. [Additional Notes](#additional-notes)

---

## User & Credential Security

### 1. Remove Root Account Access Keys

**Issue**: The root account has active access keys (check A.1)
**Severity**: CRITICAL
**Compliance**: CIS 1.3, AWS-FSBP IAM.4, PCI-DSS 8.2.1, NIST AC-6(1), SOC2 CC6.1

The root user has unrestricted access to the entire account. Long-lived root access keys are a top-tier risk and must never exist.

#### AWS Console
1. Sign in as the **root user**
2. Open the account menu (top right) -> **Security credentials**
3. Expand **Access keys**
4. For each key, click **Actions** -> **Deactivate**, then **Delete**
5. Confirm no access keys remain under the root user

#### AWS CLI
```bash
# Root keys CANNOT be managed by other IAM principals.
# Confirm whether root keys exist (account-level summary):
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
# A value of 1 means root keys exist. Delete them while signed in as root
# via the Security credentials console page (no CLI deletes root's own keys).
```

#### Python boto3
```python
import boto3

def check_root_access_keys():
    """Returns True if the root account still has access keys present."""
    iam_client = boto3.client('iam')

    try:
        summary = iam_client.get_account_summary()
        present = summary['SummaryMap'].get('AccountAccessKeysPresent', 0)
        if present:
            print("CRITICAL: root account access keys are present - "
                  "delete them via the root Security credentials page.")
        else:
            print("OK: no root account access keys.")
        return bool(present)
    except Exception as e:
        print(f"Error checking root access keys: {e}")
        return True  # fail closed

# Usage
check_root_access_keys()
```

---

### 2. Enable Hardware MFA on the Root Account

**Issue**: Root MFA not enabled, or root MFA is virtual instead of hardware (checks A.2, A.3)
**Severity**: CRITICAL
**Compliance**: CIS 1.4 (A.2), 1.5 (A.3), AWS-FSBP IAM.9, IAM.6, PCI-DSS 8.2.1, NIST IA-2(1), SOC2 CC6.1

Root must be protected with MFA, and a hardware MFA device (FIDO security key or hardware TOTP) is strongly preferred over a virtual app.

#### AWS Console
1. Sign in as the **root user** -> **Security credentials**
2. Under **Multi-factor authentication (MFA)**, click **Assign MFA device**
3. Choose **Security Key** (FIDO) or **Hardware TOTP token** (preferred over Authenticator app)
4. Follow the prompts to register the device
5. If a **virtual** MFA was previously assigned, remove it after the hardware device is active

#### AWS CLI
```bash
# Root MFA must be enrolled while signed in as root (console).
# You can verify whether the root user has MFA via the credential report:
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F, 'NR==1 || $1=="<root_account>"'
# The mfa_active column shows whether root MFA is enabled.
```

#### Python boto3
```python
import boto3
import csv
import io
import time

def root_mfa_status():
    iam_client = boto3.client('iam')

    # Ensure a fresh credential report exists.
    iam_client.generate_credential_report()
    for _ in range(10):
        try:
            report = iam_client.get_credential_report()
            break
        except iam_client.exceptions.CredentialReportNotPresentException:
            time.sleep(2)
    else:
        raise RuntimeError("credential report not ready")

    rows = csv.DictReader(io.StringIO(report['Content'].decode('utf-8')))
    for row in rows:
        if row['user'] == '<root_account>':
            enabled = row['mfa_active'] == 'true'
            print(f"Root MFA enabled: {enabled}")
            return enabled
    return False  # fail closed

# Usage
root_mfa_status()
```

---

### 3. Enforce MFA for IAM Users and Console Users

**Issue**: IAM users without MFA, and console-enabled users without MFA (checks A.4, A.10)
**Severity**: HIGH (console users), MEDIUM (all users)
**Compliance**: CIS 1.9 (A.10), AWS-FSBP IAM.5, IAM.19, NIST IA-2(1), ISO 27001 A.5.17

Every user, especially any user with a console password, must have an MFA device. Enforce it with both per-user devices and an account-wide deny policy.

#### AWS Console
1. **IAM Console** -> **Users** -> select the user -> **Security credentials** tab
2. Under **Multi-factor authentication (MFA)**, click **Assign MFA device**
3. Register a virtual or hardware MFA device
4. To enforce account-wide, attach a policy that denies actions unless MFA is present (see CLI/boto3)

#### AWS CLI
```bash
# Enable a virtual MFA device for a user (create, then enable with two codes)
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name alice \
  --outfile /tmp/alice-qr.png --bootstrap-method QRCodePNG

aws iam enable-mfa-device \
  --user-name alice \
  --serial-number arn:aws:iam::ACCOUNT_ID:mfa/alice \
  --authentication-code1 123456 \
  --authentication-code2 789012

# Account-wide enforcement: attach a deny-without-MFA policy
cat > enforce-mfa.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptSelfManageMFAWithoutMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "iam:GetUser",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" }
      }
    }
  ]
}
EOF
aws iam create-policy --policy-name EnforceMFA --policy-document file://enforce-mfa.json
```

#### Python boto3
```python
import boto3

def users_without_mfa():
    """Return console-capable users that have no MFA device."""
    iam_client = boto3.client('iam')
    offenders = []

    for user in iam_client.get_paginator('list_users').paginate():
        for u in user['Users']:
            name = u['UserName']
            mfa = iam_client.list_mfa_devices(UserName=name)['MFADevices']
            has_login = True
            try:
                iam_client.get_login_profile(UserName=name)
            except iam_client.exceptions.NoSuchEntityException:
                has_login = False
            if not mfa:
                offenders.append({'user': name, 'console': has_login})
    for o in offenders:
        sev = "HIGH" if o['console'] else "MEDIUM"
        print(f"{sev}: {o['user']} has no MFA (console={o['console']})")
    return offenders

# Usage
users_without_mfa()
```

---

### 4. Rotate and Consolidate Access Keys

**Issue**: Access keys older than 90 days, and users with multiple active keys (checks A.5, A.7)
**Severity**: MEDIUM (A.5), LOW (A.7)
**Compliance**: CIS 1.13 (A.5), AWS-FSBP IAM.3, PCI-DSS 8.3.9, NIST IA-5(1), SOC2 CC6.1

Rotate keys regularly and keep at most one active key per user (the second slot exists only to support zero-downtime rotation).

#### AWS Console
1. **IAM Console** -> **Users** -> select user -> **Security credentials**
2. Under **Access keys**, click **Create access key** to mint a replacement
3. Update applications to use the new key
4. **Deactivate** the old key, verify nothing breaks, then **Delete** it
5. Delete any surplus keys so only one active key remains

#### AWS CLI
```bash
# List keys and their ages
aws iam list-access-keys --user-name alice

# Rotate: create new, update apps, then deactivate + delete the old key
aws iam create-access-key --user-name alice
aws iam update-access-key --user-name alice --access-key-id AKIAOLD --status Inactive
aws iam delete-access-key --user-name alice --access-key-id AKIAOLD
```

#### Python boto3
```python
import boto3
from datetime import datetime, timezone

MAX_AGE_DAYS = 90

def find_stale_or_extra_keys():
    iam_client = boto3.client('iam')
    findings = []

    for page in iam_client.get_paginator('list_users').paginate():
        for u in page['Users']:
            name = u['UserName']
            keys = iam_client.list_access_keys(UserName=name)['AccessKeyMetadata']
            active = [k for k in keys if k['Status'] == 'Active']
            if len(active) > 1:
                findings.append((name, 'MULTIPLE_ACTIVE_KEYS'))
            for k in active:
                age = (datetime.now(timezone.utc) - k['CreateDate']).days
                if age > MAX_AGE_DAYS:
                    findings.append((name, f"KEY_AGE_{age}d:{k['AccessKeyId']}"))
    for name, issue in findings:
        print(f"{name}: {issue}")
    return findings

# Usage
find_stale_or_extra_keys()
```

---

### 5. Remove Unused Credentials

**Issue**: Passwords or access keys unused for 45 or more days (check A.6)
**Severity**: MEDIUM
**Compliance**: CIS 1.11, AWS-FSBP IAM.8, IAM.22, PCI-DSS 8.2.4, NIST AC-2

Disable or delete credentials that have not been used recently to shrink the attack surface.

#### AWS Console
1. **IAM Console** -> **Users** -> review the **Last activity** column
2. For a stale console password: select user -> **Security credentials** -> **Manage console access** -> **Disable**
3. For a stale access key: **Deactivate** then **Delete** it

#### AWS CLI
```bash
# Remove an unused console password (login profile)
aws iam delete-login-profile --user-name bob

# Deactivate and delete an unused access key
aws iam update-access-key --user-name bob --access-key-id AKIAUNUSED --status Inactive
aws iam delete-access-key --user-name bob --access-key-id AKIAUNUSED
```

#### Python boto3
```python
import boto3
from datetime import datetime, timezone

UNUSED_DAYS = 45

def disable_unused_credentials(dry_run=True):
    iam_client = boto3.client('iam')

    for page in iam_client.get_paginator('list_users').paginate():
        for u in page['Users']:
            name = u['UserName']
            for k in iam_client.list_access_keys(UserName=name)['AccessKeyMetadata']:
                last = iam_client.get_access_key_last_used(
                    AccessKeyId=k['AccessKeyId'])['AccessKeyLastUsed']
                used = last.get('LastUsedDate')
                # A never-used key (no LastUsedDate) still counts as unused once
                # it is older than the threshold - fall back to its CreateDate.
                age_ref = used or k['CreateDate']
                if (datetime.now(timezone.utc) - age_ref).days >= UNUSED_DAYS:
                    when = used.date() if used else f"never used, created {k['CreateDate'].date()}"
                    print(f"{name}: key {k['AccessKeyId']} unused ({when})")
                    if not dry_run:
                        iam_client.update_access_key(
                            UserName=name, AccessKeyId=k['AccessKeyId'],
                            Status='Inactive')

# Usage
disable_unused_credentials(dry_run=True)
```

---

### 6. Move Direct Permissions to Groups and Remove Inline Policies

**Issue**: Users with directly-attached managed policies or inline policies (checks A.8, A.9)
**Severity**: LOW
**Compliance**: CIS 1.14, AWS-FSBP IAM.2, IAM.1, NIST AC-6, ISO 27001 A.5.18

Manage permissions at the group level with managed policies; avoid per-user attachments and inline policies, which are hard to audit.

#### AWS Console
1. **IAM Console** -> **User groups** -> create or select a group, attach the managed policy there
2. **Users** -> select the user -> **Add user to groups**
3. On the user's **Permissions** tab, remove directly-attached policies and delete inline policies

#### AWS CLI
```bash
# Put the permission on a group and add the user to it
aws iam add-user-to-group --user-name alice --group-name Developers

# Detach a directly-attached managed policy from the user
aws iam detach-user-policy --user-name alice --policy-arn arn:aws:iam::ACCOUNT_ID:policy/SomePolicy

# Delete an inline user policy
aws iam delete-user-policy --user-name alice --policy-name InlineThing
```

#### Python boto3
```python
import boto3

def list_user_direct_permissions():
    iam_client = boto3.client('iam')
    report = {}

    for page in iam_client.get_paginator('list_users').paginate():
        for u in page['Users']:
            name = u['UserName']
            attached = iam_client.list_attached_user_policies(
                UserName=name)['AttachedPolicies']
            inline = iam_client.list_user_policies(UserName=name)['PolicyNames']
            if attached or inline:
                report[name] = {
                    'attached': [p['PolicyArn'] for p in attached],
                    'inline': inline,
                }
    for name, data in report.items():
        print(f"{name}: attached={data['attached']} inline={data['inline']}")
    return report

# Usage
list_user_direct_permissions()
```

---

### 7. Stop Using the Root Account for Daily Tasks

**Issue**: Root account used within the last 90 days (check A.11)
**Severity**: LOW
**Compliance**: NIST AC-6(2), SOC2 CC6.1 (A.11 is a native finding; CIS v5.0.0 removed the root-daily-use control and it has no FSBP control)

Reserve root for the few tasks that strictly require it. Operate day-to-day through IAM Identity Center or IAM roles.

#### AWS Console
1. Set up **IAM Identity Center** (or roles) for human and workload access
2. Ensure root has hardware MFA and no access keys (see remediations 1 and 2)
3. Store the root credentials securely and avoid signing in as root

#### AWS CLI
```bash
# Confirm last root usage from the credential report
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F, 'NR==1 || $1=="<root_account>" {print $1","$5","$11}'
# Columns shown: user, password_last_used, access_key_1_last_used_date
```

#### Python boto3
```python
import boto3
import csv
import io

def root_last_used():
    iam_client = boto3.client('iam')
    iam_client.generate_credential_report()
    report = iam_client.get_credential_report()
    rows = csv.DictReader(io.StringIO(report['Content'].decode('utf-8')))
    for row in rows:
        if row['user'] == '<root_account>':
            print(f"Root password_last_used: {row['password_last_used']}")
            return row['password_last_used']

# Usage
root_last_used()
```

---

### 8. Remove AdministratorAccess Attached Directly to Users

**Issue**: Users with the AWS-managed `AdministratorAccess` policy attached directly (check A.12)
**Severity**: HIGH
**Compliance**: PCI-DSS 7.2.x, NIST AC-6(1), ISO 27001 A.5.18 (A.12 is a native finding; no dedicated CIS/FSBP control)

Full admin should be granted through a narrowly-controlled role, not pinned to individual users.

#### AWS Console
1. **IAM Console** -> **Users** -> select the user -> **Permissions** tab
2. Find **AdministratorAccess** -> **Remove**
3. Grant only the specific permissions needed via a role or group

#### AWS CLI
```bash
aws iam detach-user-policy \
  --user-name alice \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

#### Python boto3
```python
import boto3

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

def remove_direct_admin(dry_run=True):
    iam_client = boto3.client('iam')

    for page in iam_client.get_paginator('list_users').paginate():
        for u in page['Users']:
            name = u['UserName']
            for p in iam_client.list_attached_user_policies(
                    UserName=name)['AttachedPolicies']:
                if p['PolicyArn'] == ADMIN_ARN:
                    print(f"HIGH: {name} has AdministratorAccess attached directly")
                    if not dry_run:
                        iam_client.detach_user_policy(
                            UserName=name, PolicyArn=ADMIN_ARN)

# Usage
remove_direct_admin(dry_run=True)
```

---

## Password Policy

### 9. Configure a Strong Account Password Policy

**Issue**: No password policy, or a policy weaker than baseline (checks B.1-B.8)
**Severity**: HIGH (B.1 no policy), MEDIUM (B.2 length), LOW (B.3-B.8 complexity/reuse/expiry)
**Compliance**: CIS 1.7 (B.2), 1.8 (B.7), AWS-FSBP IAM.7, IAM.10-IAM.17, PCI-DSS 8.3.6, NIST IA-5(1), ISO 27001 A.5.17

A single account-wide password policy fixes B.1 through B.8 at once. The settings below map directly to each check:

- **B.1** no policy -> create the policy
- **B.2** minimum length < 14 -> `--minimum-password-length 14`
- **B.3** no uppercase required -> `--require-uppercase-characters`
- **B.4** no lowercase required -> `--require-lowercase-characters`
- **B.5** no number required -> `--require-numbers`
- **B.6** no symbol required -> `--require-symbols`
- **B.7** reuse prevention < 24 -> `--password-reuse-prevention 24`
- **B.8** no 90-day expiry -> `--max-password-age 90`

#### AWS Console
1. **IAM Console** -> **Account settings**
2. Under **Password policy**, click **Edit**
3. Set: minimum length **14**, require uppercase, lowercase, numbers, and symbols
4. Set **Prevent password reuse** to **24**, and **Expire passwords** to **90** days
5. Click **Save changes**

#### AWS CLI
```bash
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --require-numbers \
  --require-symbols \
  --password-reuse-prevention 24 \
  --max-password-age 90 \
  --allow-users-to-change-password

# Verify
aws iam get-account-password-policy
```

#### Python boto3
```python
import boto3

def set_strong_password_policy():
    iam_client = boto3.client('iam')
    try:
        iam_client.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            RequireNumbers=True,
            RequireSymbols=True,
            PasswordReusePrevention=24,
            MaxPasswordAge=90,
            AllowUsersToChangePassword=True,
        )
        print("Strong account password policy applied.")
    except Exception as e:
        print(f"Error setting password policy: {e}")

# Usage
set_strong_password_policy()
```

---

## Managed Policy Security

### 10. Remove Full Admin From Customer-Managed Policies

**Issue**: Customer-managed policies granting full `*:*` admin (check C.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, PCI-DSS 7.2.x, NIST AC-6(1), ISO 27001 A.5.15 (CIS v5.0.0 removed the full-admin-policy control)

Rewrite any policy that allows `Action: *` on `Resource: *` to grant only the specific actions and resources required.

#### AWS Console
1. **IAM Console** -> **Policies** -> select the customer-managed policy
2. **Edit** -> remove the `Allow *:*` statement, scope `Action` and `Resource`
3. **Next** -> **Save changes** as a new policy version

#### AWS CLI
```bash
# Inspect the default version document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TooBroad \
  --version-id v1

# Create a scoped replacement version and set it as default
aws iam create-policy-version \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/TooBroad \
  --policy-document file://scoped-policy.json \
  --set-as-default
```

#### Python boto3
```python
import boto3

def find_full_admin_customer_policies():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            doc = ver['PolicyVersion']['Document']
            for stmt in _as_list(doc.get('Statement', [])):
                if stmt.get('Effect') == 'Allow' \
                        and '*' in _as_list(stmt.get('Action', [])) \
                        and '*' in _as_list(stmt.get('Resource', [])):
                    offenders.append(p['Arn'])
    for arn in offenders:
        print(f"HIGH full-admin policy: {arn}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_full_admin_customer_policies()
```

---

### 11. Replace Wildcard Service Actions

**Issue**: Policies using wildcard service actions such as `s3:*` (check C.2)
**Severity**: LOW
**Compliance**: AWS-FSBP IAM.1, NIST AC-6, ISO 27001 A.5.15

Replace `service:*` with the explicit actions the workload needs (for example `s3:GetObject`, `s3:PutObject`).

#### AWS Console
1. **IAM Console** -> **Policies** -> select the policy -> **Edit**
2. Replace each `service:*` action with the specific API actions required
3. Save a new version

#### AWS CLI
```bash
# Review, then publish a tightened version
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/WideService \
  --version-id v1
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/WideService \
  --policy-document file://explicit-actions.json --set-as-default
```

#### Python boto3
```python
import boto3

def find_wildcard_service_actions():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            for stmt in _as_list(ver['PolicyVersion']['Document'].get('Statement', [])):
                if stmt.get('Effect') != 'Allow':
                    continue
                for action in _as_list(stmt.get('Action', [])):
                    if action.endswith(':*'):
                        offenders.append((p['Arn'], action))
    for arn, action in offenders:
        print(f"LOW wildcard action {action} in {arn}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_wildcard_service_actions()
```

---

### 12. Restrict iam:PassRole

**Issue**: Policies allowing `iam:PassRole` on a wildcard resource (check C.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, NIST AC-6(1), ISO 27001 A.5.15

`iam:PassRole` on `*` lets a principal hand any role to a service. Restrict the resource to the exact role ARNs and add an `iam:PassedToService` condition.

#### AWS Console
1. **IAM Console** -> **Policies** -> select the policy -> **Edit**
2. Change the `iam:PassRole` statement `Resource` from `*` to specific role ARNs
3. Add a `Condition` with `iam:PassedToService` for the intended service
4. Save a new version

#### AWS CLI
```bash
cat > passrole-scoped.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::ACCOUNT_ID:role/AppExecutionRole",
      "Condition": {
        "StringEquals": { "iam:PassedToService": "ec2.amazonaws.com" }
      }
    }
  ]
}
EOF
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PassRoleWide \
  --policy-document file://passrole-scoped.json --set-as-default
```

#### Python boto3
```python
import boto3

def find_passrole_wildcards():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            for stmt in _as_list(ver['PolicyVersion']['Document'].get('Statement', [])):
                actions = [a.lower() for a in _as_list(stmt.get('Action', []))]
                if stmt.get('Effect') == 'Allow' and 'iam:passrole' in actions \
                        and '*' in _as_list(stmt.get('Resource', [])):
                    offenders.append(p['Arn'])
    for arn in offenders:
        print(f"HIGH PassRole on * in {arn}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_passrole_wildcards()
```

---

### 13. Avoid NotAction With Allow

**Issue**: Policies combining `NotAction` with `Allow` (check C.4)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP IAM.1, NIST AC-6, ISO 27001 A.5.15

`NotAction` + `Allow` grants everything except the listed actions, which almost always over-permits. List the explicit allowed actions instead.

#### AWS Console
1. **IAM Console** -> **Policies** -> select the policy -> **Edit**
2. Replace the `NotAction`+`Allow` statement with an `Action` list of only what is intended
3. Save a new version

#### AWS CLI
```bash
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/NotActionAllow \
  --version-id v1
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/NotActionAllow \
  --policy-document file://explicit-allow.json --set-as-default
```

#### Python boto3
```python
import boto3

def find_notaction_allow():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            for stmt in _as_list(ver['PolicyVersion']['Document'].get('Statement', [])):
                if stmt.get('Effect') == 'Allow' and 'NotAction' in stmt:
                    offenders.append(p['Arn'])
    for arn in offenders:
        print(f"MEDIUM NotAction+Allow in {arn}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_notaction_allow()
```

---

### 14. Delete Unused Customer-Managed Policies

**Issue**: Customer-managed policies with zero attachments (check C.5)
**Severity**: LOW
**Compliance**: AWS-FSBP IAM.1, NIST CM-7, ISO 27001 A.5.15

Unattached policies are clutter that can be attached later by mistake. Remove the ones you no longer need.

#### AWS Console
1. **IAM Console** -> **Policies** -> filter by **Customer managed**
2. Sort by **Attachments** = 0
3. Select the policy -> **Delete**

#### AWS CLI
```bash
# List customer-managed policies that have no attachments
aws iam list-policies --scope Local \
  --query 'Policies[?AttachmentCount==`0`].Arn' --output text

# Delete one. delete-policy fails with DeleteConflict if non-default versions
# exist, so remove those first:
ARN=arn:aws:iam::ACCOUNT_ID:policy/Unused
for v in $(aws iam list-policy-versions --policy-arn "$ARN" \
  --query 'Versions[?!IsDefaultVersion].VersionId' --output text); do
  aws iam delete-policy-version --policy-arn "$ARN" --version-id "$v"
done
aws iam delete-policy --policy-arn "$ARN"
```

#### Python boto3
```python
import boto3

def delete_unused_policies(dry_run=True):
    iam_client = boto3.client('iam')

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            if p['AttachmentCount'] == 0:
                print(f"LOW unused policy: {p['Arn']}")
                if not dry_run:
                    # remove non-default versions first
                    for v in iam_client.list_policy_versions(
                            PolicyArn=p['Arn'])['Versions']:
                        if not v['IsDefaultVersion']:
                            iam_client.delete_policy_version(
                                PolicyArn=p['Arn'], VersionId=v['VersionId'])
                    iam_client.delete_policy(PolicyArn=p['Arn'])

# Usage
delete_unused_policies(dry_run=True)
```

---

## Role Security

### 15. Scope Down Admin Roles

**Issue**: Roles with full admin access (check D.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, NIST AC-6(1), ISO 27001 A.5.15 (CIS v5.0.0 removed the full-admin control)

Replace `AdministratorAccess` on a role with a scoped policy that grants only what the role needs to do its job.

#### AWS Console
1. **IAM Console** -> **Roles** -> select the role -> **Permissions** tab
2. **Remove** `AdministratorAccess`
3. Attach a least-privilege policy scoped to the role's purpose

#### AWS CLI
```bash
aws iam detach-role-policy \
  --role-name AppRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam attach-role-policy \
  --role-name AppRole \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AppLeastPrivilege
```

#### Python boto3
```python
import boto3

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

def find_admin_roles():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_roles').paginate():
        for r in page['Roles']:
            if r['Path'].startswith('/aws-service-role/'):
                continue  # skip service-linked roles
            for p in iam_client.list_attached_role_policies(
                    RoleName=r['RoleName'])['AttachedPolicies']:
                if p['PolicyArn'] == ADMIN_ARN:
                    offenders.append(r['RoleName'])
    for name in offenders:
        print(f"HIGH admin role: {name}")
    return offenders

# Usage
find_admin_roles()
```

---

### 16. Remove Wildcard Trust Principals

**Issue**: Roles with a wildcard principal (`*`) in the trust policy (check D.2)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP IAM.1, PCI-DSS 7.2.x, NIST AC-6(1), ISO 27001 A.5.15

A trust policy that trusts `*` lets anyone assume the role. Restrict the trust to specific principals and add Org/ExternalId conditions.

#### AWS Console
1. **IAM Console** -> **Roles** -> select role -> **Trust relationships** tab
2. **Edit trust policy** -> replace `"Principal": "*"` with specific principal ARNs
3. Add a `Condition` (for example `aws:PrincipalOrgID` or `sts:ExternalId`)
4. **Update policy**

#### AWS CLI
```bash
cat > trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::TRUSTED_ACCOUNT_ID:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "aws:PrincipalOrgID": "o-xxxxxxxxxx" }
      }
    }
  ]
}
EOF
aws iam update-assume-role-policy --role-name AppRole \
  --policy-document file://trust.json
```

#### Python boto3
```python
import boto3

def find_wildcard_trust_roles():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_roles').paginate():
        for r in page['Roles']:
            doc = r.get('AssumeRolePolicyDocument', {})
            for stmt in _as_list(doc.get('Statement', [])):
                principal = stmt.get('Principal')
                if _principal_has_wildcard(principal):
                    offenders.append(r['RoleName'])
    for name in offenders:
        print(f"CRITICAL wildcard trust principal: {name}")
    return offenders

def _principal_has_wildcard(principal):
    # Matches "*", {"AWS": "*"}, and the list form {"AWS": ["*", ...]}
    if principal == '*':
        return True
    if isinstance(principal, dict):
        for v in principal.values():  # AWS / Service / Federated
            if v == '*' or (isinstance(v, list) and '*' in v):
                return True
    return False

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_wildcard_trust_roles()
```

---

### 17. Tighten Overly-Permissive Inline Role Policies

**Issue**: Roles with overly-permissive inline policies (check D.4)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, NIST AC-6, ISO 27001 A.5.15

Remove wildcard `Action`/`Resource` from inline role policies and scope them to least privilege (or convert to a reviewed managed policy).

#### AWS Console
1. **IAM Console** -> **Roles** -> select role -> **Permissions** tab
2. Expand the inline policy -> **Edit**
3. Replace wildcard actions/resources with explicit values, or **Delete** and attach a scoped managed policy

#### AWS CLI
```bash
# Inspect an inline role policy
aws iam get-role-policy --role-name AppRole --policy-name InlineWide

# Replace it with a scoped document (same name overwrites)
aws iam put-role-policy --role-name AppRole --policy-name InlineWide \
  --policy-document file://scoped-inline.json
```

#### Python boto3
```python
import boto3

def find_wide_inline_role_policies():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_roles').paginate():
        for r in page['Roles']:
            name = r['RoleName']
            for pol_name in iam_client.list_role_policies(
                    RoleName=name)['PolicyNames']:
                doc = iam_client.get_role_policy(
                    RoleName=name, PolicyName=pol_name)['PolicyDocument']
                for stmt in _as_list(doc.get('Statement', [])):
                    if stmt.get('Effect') == 'Allow' \
                            and '*' in _as_list(stmt.get('Action', [])) \
                            and '*' in _as_list(stmt.get('Resource', [])):
                        offenders.append((name, pol_name))
    for name, pol in offenders:
        print(f"HIGH wide inline policy {pol} on role {name}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_wide_inline_role_policies()
```

---

### 18. Delete Unused Roles

**Issue**: Roles unused for 90 or more days (check D.5)
**Severity**: LOW
**Compliance**: NIST AC-2, CM-7, ISO 27001 A.5.18 (D.5 is a native finding; no dedicated CIS/FSBP control)

Review roles with no recent activity and delete the ones that are no longer needed.

#### AWS Console
1. **IAM Console** -> **Roles** -> review the **Last activity** column
2. Confirm the role is truly unused (check CloudTrail if unsure)
3. Detach policies and delete inline policies, then **Delete role**

#### AWS CLI
```bash
# Check role last-used
aws iam get-role --role-name OldRole --query 'Role.RoleLastUsed'

# delete-role fails with DeleteConflict unless you first detach managed policies,
# delete inline policies, and remove the role from any instance profile:
ROLE=OldRole
for p in $(aws iam list-attached-role-policies --role-name "$ROLE" \
  --query 'AttachedPolicies[].PolicyArn' --output text); do
  aws iam detach-role-policy --role-name "$ROLE" --policy-arn "$p"
done
for p in $(aws iam list-role-policies --role-name "$ROLE" \
  --query 'PolicyNames[]' --output text); do
  aws iam delete-role-policy --role-name "$ROLE" --policy-name "$p"
done
aws iam delete-role --role-name "$ROLE"
```

#### Python boto3
```python
import boto3
from datetime import datetime, timezone

UNUSED_DAYS = 90

def find_unused_roles():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_roles').paginate():
        for r in page['Roles']:
            if r['Path'].startswith('/aws-service-role/'):
                continue
            last = r.get('RoleLastUsed', {}).get('LastUsedDate')
            if last is None or (datetime.now(timezone.utc) - last).days >= UNUSED_DAYS:
                offenders.append(r['RoleName'])
    for name in offenders:
        print(f"LOW unused role: {name}")
    return offenders

# Usage
find_unused_roles()
```

---

## Group Security

### 19. Scope Down Admin Groups

**Issue**: Groups with full admin access (check E.1)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, NIST AC-6(1), ISO 27001 A.5.15 (CIS v5.0.0 removed the full-admin control)

Replace `AdministratorAccess` on a group with scoped policies and tightly control membership.

#### AWS Console
1. **IAM Console** -> **User groups** -> select the group -> **Permissions** tab
2. **Remove** `AdministratorAccess`
3. Attach a least-privilege policy and review the members list

#### AWS CLI
```bash
aws iam detach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws iam attach-group-policy \
  --group-name Admins \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/ScopedOps
```

#### Python boto3
```python
import boto3

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

def find_admin_groups():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_groups').paginate():
        for g in page['Groups']:
            for p in iam_client.list_attached_group_policies(
                    GroupName=g['GroupName'])['AttachedPolicies']:
                if p['PolicyArn'] == ADMIN_ARN:
                    offenders.append(g['GroupName'])
    for name in offenders:
        print(f"HIGH admin group: {name}")
    return offenders

# Usage
find_admin_groups()
```

---

### 20. Remove Empty Groups and Assign Ungrouped Users

**Issue**: Empty IAM groups, and users not in any group (checks E.2, E.3)
**Severity**: LOW (E.2), MEDIUM (E.3)
**Compliance**: AWS-FSBP IAM.2, NIST AC-2, ISO 27001 A.5.18

Manage permissions through groups: delete groups with no members and place every user in an appropriate group.

#### AWS Console
1. **IAM Console** -> **User groups** -> delete any group with 0 members
2. **Users** -> for each user not in a group, **Add user to groups**

#### AWS CLI
```bash
# Delete an empty group
aws iam delete-group --group-name EmptyGroup

# Add an ungrouped user to a group
aws iam add-user-to-group --user-name carol --group-name Developers
```

#### Python boto3
```python
import boto3

def audit_group_membership():
    iam_client = boto3.client('iam')
    empty_groups, grouped_users = [], set()

    for page in iam_client.get_paginator('list_groups').paginate():
        for g in page['Groups']:
            members = iam_client.get_group(GroupName=g['GroupName'])['Users']
            if not members:
                empty_groups.append(g['GroupName'])
            grouped_users.update(u['UserName'] for u in members)

    ungrouped = []
    for page in iam_client.get_paginator('list_users').paginate():
        for u in page['Users']:
            if u['UserName'] not in grouped_users:
                ungrouped.append(u['UserName'])

    print(f"LOW empty groups: {empty_groups}")
    print(f"MEDIUM ungrouped users: {ungrouped}")
    return empty_groups, ungrouped

# Usage
audit_group_membership()
```

---

## Account Settings

### 21. Enable IAM Access Analyzer (External Access)

**Issue**: IAM Access Analyzer (external access) is not enabled (check F.1)
**Severity**: HIGH
**Compliance**: CIS 1.19, AWS-FSBP IAM.28, NIST AU-2, SI-4, ISO 27001 A.8.9

Access Analyzer continuously identifies resources shared with external principals. Enable an account or organization analyzer in every active region.

#### AWS Console
1. **IAM Console** -> **Access Analyzer** -> **Analyzers**
2. Click **Create analyzer**
3. Choose **External access analysis**, scope **Current account** (or organization)
4. Click **Create analyzer**

#### AWS CLI
```bash
aws accessanalyzer create-analyzer \
  --analyzer-name external-access \
  --type ACCOUNT

# Verify
aws accessanalyzer list-analyzers --query 'analyzers[].{name:name,type:type,status:status}'
```

#### Python boto3
```python
import boto3

def ensure_external_access_analyzer(region='us-east-1'):
    client = boto3.client('accessanalyzer', region_name=region)
    existing = client.list_analyzers(type='ACCOUNT')['analyzers']
    if any(a['status'] == 'ACTIVE' for a in existing):
        print("OK: external-access analyzer already active.")
        return
    client.create_analyzer(analyzerName='external-access', type='ACCOUNT')
    print(f"Created external-access analyzer in {region}.")

# Usage
ensure_external_access_analyzer()
```

---

### 22. Review and Resolve Access Analyzer Findings

**Issue**: Access Analyzer has active findings (check F.6)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.28, NIST AU-2, SI-4, AU-6, ISO 27001 A.8.9 (F.6 is a native finding, no dedicated CIS control)

Each active finding represents a resource reachable by an external principal. Confirm whether the access is intended; remove it if not, then archive the finding.

#### AWS Console
1. **IAM Console** -> **Access Analyzer** -> select the analyzer -> **Findings**
2. Open each **Active** finding and review the external principal and resource
3. Remove the unintended access at the resource (policy/trust/grant)
4. **Archive** resolved findings; create archive rules for known-good access

#### AWS CLI
```bash
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)

# List active findings
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" \
  --filter '{"status":{"eq":["ACTIVE"]}}'

# After remediating the resource, archive a finding
aws accessanalyzer update-findings --analyzer-arn "$ANALYZER_ARN" \
  --ids FINDING_ID --status ARCHIVED
```

#### Python boto3
```python
import boto3

def list_active_findings(region='us-east-1'):
    client = boto3.client('accessanalyzer', region_name=region)
    analyzers = client.list_analyzers(type='ACCOUNT')['analyzers']
    if not analyzers:
        print("No analyzer configured - see remediation 21.")
        return []
    arn = analyzers[0]['arn']
    findings = client.list_findings(
        analyzerArn=arn, filter={'status': {'eq': ['ACTIVE']}})['findings']
    for f in findings:
        print(f"ACTIVE: {f.get('resourceType')} {f.get('resource')} "
              f"-> {f.get('principal')}")
    return findings

# Usage
list_active_findings()
```

---

### 23. Enable the Unused-Access Analyzer

**Issue**: No Access Analyzer unused-access analyzer is enabled (check F.7)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP IAM.28, NIST AC-2, CM-7, ISO 27001 A.5.18

The unused-access analyzer surfaces unused roles, permissions, and access keys so you can right-size them.

#### AWS Console
1. **IAM Console** -> **Access Analyzer** -> **Analyzers** -> **Create analyzer**
2. Choose **Unused access analysis**
3. Set a tracking period (for example 90 days) and **Create analyzer**

#### AWS CLI
```bash
aws accessanalyzer create-analyzer \
  --analyzer-name unused-access \
  --type ACCOUNT_UNUSED_ACCESS \
  --configuration '{"unusedAccess":{"unusedAccessAge":90}}'
```

#### Python boto3
```python
import boto3

def ensure_unused_access_analyzer(region='us-east-1', age_days=90):
    client = boto3.client('accessanalyzer', region_name=region)
    existing = client.list_analyzers(type='ACCOUNT_UNUSED_ACCESS')['analyzers']
    if any(a['status'] == 'ACTIVE' for a in existing):
        print("OK: unused-access analyzer already active.")
        return
    client.create_analyzer(
        analyzerName='unused-access',
        type='ACCOUNT_UNUSED_ACCESS',
        configuration={'unusedAccess': {'unusedAccessAge': age_days}},
    )
    print(f"Created unused-access analyzer ({age_days}d) in {region}.")

# Usage
ensure_unused_access_analyzer()
```

---

### 24. Create a Support Role

**Issue**: No IAM role with the `AWSSupportAccess` managed policy (check F.2)
**Severity**: LOW
**Compliance**: CIS 1.16, AWS-FSBP IAM.18, NIST IR-7, ISO 27001 A.5.24

A dedicated support role lets staff manage support cases without broad permissions.

#### AWS Console
1. **IAM Console** -> **Roles** -> **Create role**
2. Trust the principals who should manage support cases
3. Attach the **AWSSupportAccess** managed policy -> **Create role**

#### AWS CLI
```bash
cat > support-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::ACCOUNT_ID:root" },
      "Action": "sts:AssumeRole",
      "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
    }
  ]
}
EOF
aws iam create-role --role-name SupportRole \
  --assume-role-policy-document file://support-trust.json
aws iam attach-role-policy --role-name SupportRole \
  --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess
```

#### Python boto3
```python
import boto3
import json

def create_support_role(account_id):
    iam_client = boto3.client('iam')
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }],
    }
    iam_client.create_role(RoleName='SupportRole',
                           AssumeRolePolicyDocument=json.dumps(trust))
    iam_client.attach_role_policy(
        RoleName='SupportRole',
        PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess')
    print("SupportRole created with AWSSupportAccess.")

# Usage
# create_support_role('123456789012')
```

---

### 25. Remove Expired and Legacy IAM Certificates

**Issue**: Expired SSL/TLS certificates in IAM, and certificates managed in IAM rather than ACM (checks F.3, F.5)
**Severity**: MEDIUM (F.3 expired), LOW (F.5 legacy)
**Compliance**: AWS-FSBP IAM.26, NIST SC-12, SC-17, ISO 27001 A.8.24

Delete expired IAM server certificates and migrate certificate management to AWS Certificate Manager (ACM).

#### AWS Console
1. IAM server certificates are not shown in the modern console; use the CLI to list and delete them
2. In **AWS Certificate Manager**, request or import the replacement certificate
3. Update the consuming resource (load balancer, CloudFront) to the ACM certificate

#### AWS CLI
```bash
# List IAM server certificates and their expiry
aws iam list-server-certificates \
  --query 'ServerCertificateMetadataList[].{name:ServerCertificateName,exp:Expiration}'

# Delete an expired or legacy IAM server certificate (after moving consumers to ACM)
aws iam delete-server-certificate --server-certificate-name old-cert
```

#### Python boto3
```python
import boto3
from datetime import datetime, timezone

def find_expired_iam_certs():
    iam_client = boto3.client('iam')
    expired, legacy = [], []

    for c in iam_client.list_server_certificates(
            )['ServerCertificateMetadataList']:
        legacy.append(c['ServerCertificateName'])
        if c['Expiration'] < datetime.now(timezone.utc):
            expired.append(c['ServerCertificateName'])

    print(f"MEDIUM expired IAM certs: {expired}")
    print(f"LOW IAM-managed certs (migrate to ACM): {legacy}")
    return expired, legacy

# Usage
find_expired_iam_certs()
```

---

### 26. Restrict CloudShell Full Access

**Issue**: Identities with `AWSCloudShellFullAccess` attached (check F.4)
**Severity**: MEDIUM
**Compliance**: AWS-FSBP IAM.27, NIST AC-6, ISO 27001 A.5.15

`AWSCloudShellFullAccess` allows file transfer in and out of CloudShell, which can be a data-exfiltration path. Detach it and grant narrower CloudShell permissions.

#### AWS Console
1. **IAM Console** -> find the user, group, or role with **AWSCloudShellFullAccess**
2. On its **Permissions** tab, **Remove** the policy
3. Attach a scoped policy that allows only the required CloudShell actions

#### AWS CLI
```bash
CLOUDSHELL_ARN=arn:aws:iam::aws:policy/AWSCloudShellFullAccess

# Detach from a user / group / role as applicable
aws iam detach-user-policy  --user-name  alice  --policy-arn "$CLOUDSHELL_ARN"
aws iam detach-group-policy --group-name Devs   --policy-arn "$CLOUDSHELL_ARN"
aws iam detach-role-policy  --role-name  AppRole --policy-arn "$CLOUDSHELL_ARN"
```

#### Python boto3
```python
import boto3

CLOUDSHELL_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"

def find_cloudshell_full_access():
    iam_client = boto3.client('iam')
    users, groups, roles = [], [], []
    # Paginate - an account can have more than one page of attached entities.
    for page in iam_client.get_paginator('list_entities_for_policy').paginate(
            PolicyArn=CLOUDSHELL_ARN):
        users += page.get('PolicyUsers', [])
        groups += page.get('PolicyGroups', [])
        roles += page.get('PolicyRoles', [])
    for u in users:
        print(f"MEDIUM user with CloudShellFullAccess: {u['UserName']}")
    for g in groups:
        print(f"MEDIUM group with CloudShellFullAccess: {g['GroupName']}")
    for r in roles:
        print(f"MEDIUM role with CloudShellFullAccess: {r['RoleName']}")
    return {'users': users, 'groups': groups, 'roles': roles}

# Usage
find_cloudshell_full_access()
```

---

## Privilege Escalation & Trust

### 27. Remediate Privilege-Escalation Paths

**Issue**: Customer-managed or inline policies enabling privilege escalation (checks G.1, G.2)
**Severity**: CRITICAL
**Compliance**: AWS-FSBP IAM.1, PCI-DSS 7.2.x, NIST AC-6(1), AC-6(2), ISO 27001 A.8.2

A policy enables privilege escalation when its effective `Allow` set is a superset of a known escalation path (for example `iam:CreatePolicyVersion`; `iam:PassRole` paired with `ec2:RunInstances`/`lambda:CreateFunction`; `iam:AttachUserPolicy`; `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`). Remove the dangerous action combination or constrain it with conditions and a permissions boundary.

#### AWS Console
1. **IAM Console** -> **Policies** (G.1, customer-managed) or the principal's inline policy (G.2)
2. **Edit** and remove the escalation-enabling action(s), or split them across separate, reviewed roles
3. Attach a **permissions boundary** to cap the principal's effective permissions
4. Save a new version

#### AWS CLI
```bash
# Inspect the offending customer-managed policy (G.1)
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/Escalatable \
  --version-id v1

# Publish a remediated version
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/Escalatable \
  --policy-document file://no-escalation.json --set-as-default

# For inline policies (G.2), overwrite or delete
aws iam delete-user-policy --user-name alice --policy-name InlineEscalation

# Apply a permissions boundary to cap the principal
aws iam put-user-permissions-boundary --user-name alice \
  --permissions-boundary arn:aws:iam::ACCOUNT_ID:policy/Boundary
```

#### Python boto3
```python
import boto3

# A representative subset of escalation-enabling actions to flag for review.
ESCALATION_ACTIONS = {
    'iam:createpolicyversion', 'iam:setdefaultpolicyversion',
    'iam:attachuserpolicy', 'iam:attachrolepolicy', 'iam:attachgrouppolicy',
    'iam:putuserpolicy', 'iam:putrolepolicy', 'iam:putgrouppolicy',
    'iam:createaccesskey', 'iam:createloginprofile', 'iam:updateloginprofile',
    'iam:updateassumerolepolicy', 'iam:passrole',
}

def scan_customer_policies_for_escalation():
    iam_client = boto3.client('iam')
    flagged = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            allowed = set()
            for stmt in _as_list(ver['PolicyVersion']['Document'].get('Statement', [])):
                if stmt.get('Effect') == 'Allow':
                    allowed.update(a.lower() for a in _as_list(stmt.get('Action', [])))
            hits = {a for a in ESCALATION_ACTIONS
                    if a in allowed or '*' in allowed or a.split(':')[0] + ':*' in allowed}
            if hits:
                flagged.append((p['Arn'], sorted(hits)))
    for arn, hits in flagged:
        print(f"CRITICAL escalation actions in {arn}: {hits}")
    return flagged

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
scan_customer_policies_for_escalation()
```

---

### 28. Restrict sts:AssumeRole on All Resources

**Issue**: Policies allowing `sts:AssumeRole` on `*` (check G.3)
**Severity**: HIGH
**Compliance**: AWS-FSBP IAM.1, NIST AC-6(1), ISO 27001 A.5.15

Restrict the `Resource` of any `sts:AssumeRole` grant to the specific role ARNs the principal legitimately needs to assume.

#### AWS Console
1. **IAM Console** -> open the policy containing `sts:AssumeRole` on `*`
2. **Edit** -> change `Resource` from `*` to the exact role ARN(s)
3. Save a new version

#### AWS CLI
```bash
cat > assume-scoped.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::ACCOUNT_ID:role/DeployRole",
        "arn:aws:iam::ACCOUNT_ID:role/ReadOnlyRole"
      ]
    }
  ]
}
EOF
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AssumeWide \
  --policy-document file://assume-scoped.json --set-as-default
```

#### Python boto3
```python
import boto3

def find_assumerole_wildcards():
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_policies').paginate(Scope='Local'):
        for p in page['Policies']:
            ver = iam_client.get_policy_version(
                PolicyArn=p['Arn'], VersionId=p['DefaultVersionId'])
            for stmt in _as_list(ver['PolicyVersion']['Document'].get('Statement', [])):
                actions = [a.lower() for a in _as_list(stmt.get('Action', []))]
                if stmt.get('Effect') == 'Allow' \
                        and ('sts:assumerole' in actions or 'sts:*' in actions) \
                        and '*' in _as_list(stmt.get('Resource', [])):
                    offenders.append(p['Arn'])
    for arn in offenders:
        print(f"HIGH sts:AssumeRole on * in {arn}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
find_assumerole_wildcards()
```

---

### 29. Add Confused-Deputy Guards to Cross-Account Trust

**Issue**: Cross-account trust missing `ExternalId`/`PrincipalOrgID`, and roles trusting another AWS account (checks G.4, G.5)
**Severity**: HIGH (G.4), MEDIUM (G.5 - review)
**Compliance**: NIST AC-17, AC-6, ISO 27001 A.8.3, A.8.2

A cross-account role should constrain who can assume it. Add `sts:ExternalId` (third-party access) or `aws:PrincipalOrgID` (intra-Organization access) to the trust policy. G.5 is a review warning: confirm the external account is intended; if not, remove the principal.

#### AWS Console
1. **IAM Console** -> **Roles** -> select the cross-account role -> **Trust relationships**
2. **Edit trust policy** -> add a `Condition`:
   - third-party: `"StringEquals": {"sts:ExternalId": "UNIQUE_ID"}`
   - intra-Org: `"StringEquals": {"aws:PrincipalOrgID": "o-xxxxxxxxxx"}`
3. **Update policy**; remove the principal entirely if the trust is unintended

#### AWS CLI
```bash
cat > trust-guarded.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::THIRD_PARTY_ACCOUNT_ID:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "a-unique-shared-secret" }
      }
    }
  ]
}
EOF
aws iam update-assume-role-policy --role-name VendorRole \
  --policy-document file://trust-guarded.json
```

#### Python boto3
```python
import boto3

def find_unguarded_cross_account_trust(my_account_id):
    iam_client = boto3.client('iam')
    offenders = []

    for page in iam_client.get_paginator('list_roles').paginate():
        for r in page['Roles']:
            doc = r.get('AssumeRolePolicyDocument', {})
            for stmt in _as_list(doc.get('Statement', [])):
                principal = stmt.get('Principal', {})
                aws_principals = _as_list(principal.get('AWS', [])) \
                    if isinstance(principal, dict) else []
                external = any(my_account_id not in str(p) for p in aws_principals)
                if not external:
                    continue
                cond = stmt.get('Condition', {})
                flat = str(cond).lower()
                guarded = 'externalid' in flat or 'principalorgid' in flat
                sev = "MEDIUM (review)" if guarded else "HIGH"
                offenders.append((r['RoleName'], sev))
    for name, sev in offenders:
        print(f"{sev}: cross-account trust on role {name}")
    return offenders

def _as_list(value):
    return value if isinstance(value, list) else [value]

# Usage
# find_unguarded_cross_account_trust('123456789012')
```

---

## Quick Reference Commands

### Read-Only Audit Script

```bash
#!/bin/bash
# iam-quick-audit.sh - read-only checks that mirror common scanner findings

echo "== Root access keys present (1 = bad) =="
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'

echo "== Account password policy =="
aws iam get-account-password-policy 2>/dev/null || echo "NO PASSWORD POLICY (B.1)"

echo "== Access Analyzer (external) =="
aws accessanalyzer list-analyzers --query 'analyzers[?type==`ACCOUNT`].status' \
  --output text || echo "none"

echo "== Users with AdministratorAccess attached directly =="
for u in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-attached-user-policies --user-name "$u" \
    --query "AttachedPolicies[?PolicyArn=='arn:aws:iam::aws:policy/AdministratorAccess'].PolicyName" \
    --output text | grep -q AdministratorAccess && echo "  $u"
done

echo "== Generate credential report (MFA, key age, last used) =="
aws iam generate-credential-report >/dev/null
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

### Python Bulk Hardening Function

```python
import boto3


def apply_account_baseline(account_id, region='us-east-1'):
    """Apply account-wide IAM baseline controls (idempotent)."""
    iam_client = boto3.client('iam')

    # 1. Strong password policy (B.1-B.8)
    iam_client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
        PasswordReusePrevention=24,
        MaxPasswordAge=90,
        AllowUsersToChangePassword=True,
    )
    print("OK: password policy")

    # 2. Access Analyzer: external + unused-access (F.1, F.7)
    aa = boto3.client('accessanalyzer', region_name=region)
    if not aa.list_analyzers(type='ACCOUNT')['analyzers']:
        aa.create_analyzer(analyzerName='external-access', type='ACCOUNT')
        print("OK: external-access analyzer")
    if not aa.list_analyzers(type='ACCOUNT_UNUSED_ACCESS')['analyzers']:
        aa.create_analyzer(
            analyzerName='unused-access', type='ACCOUNT_UNUSED_ACCESS',
            configuration={'unusedAccess': {'unusedAccessAge': 90}})
        print("OK: unused-access analyzer")

    print("Baseline applied. Re-run the scanner to verify.")


# Usage
# apply_account_baseline('123456789012')
```

---

## Additional Notes

### AWS IAM Permissions Required

To execute these remediation steps, the operating principal needs IAM administrative permissions. A practical (still scoped) policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*",
                "access-analyzer:*",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

> Remediation requires write access to IAM; the **scanner itself** only needs read-only permissions (see the README IAM policy). Apply remediation changes from a separate, tightly-controlled administrative principal.

### Validation Commands

After applying remediations, verify with:

```bash
# Re-run the IAM Security Scanner
iam-security-scanner security --compliance-only

# Spot-check specific controls
aws iam get-account-password-policy
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
aws accessanalyzer list-analyzers --query 'analyzers[].{name:name,type:type,status:status}'
```

### Emergency Response

For an active credential-compromise incident:

```bash
# 1. Deactivate a suspected-compromised access key immediately
aws iam update-access-key --user-name SUSPECT --access-key-id AKIA... --status Inactive

# 2. Attach a deny-all boundary / detach permissions from the principal
aws iam put-user-permissions-boundary --user-name SUSPECT \
  --permissions-boundary arn:aws:iam::ACCOUNT_ID:policy/DenyAllBoundary

# 3. Force-reset the console password (or delete the login profile)
aws iam delete-login-profile --user-name SUSPECT

# 4. Review recent activity for the principal in CloudTrail, then rotate
#    any keys/roles it could reach.
```

This comprehensive remediation guide provides solutions for all security vulnerabilities detected by the IAM Security Scanner. Each remediation includes multiple implementation methods to accommodate different operational preferences and automation requirements.

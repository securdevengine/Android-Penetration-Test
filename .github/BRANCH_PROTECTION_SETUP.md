# Branch Protection Rules Setup Guide

This document provides step-by-step instructions for setting up branch protection rules to ensure secure code merging from development to main branch.

## 🛡️ Branch Protection Configuration

### Step 1: Access Repository Settings

1. Navigate to your GitHub repository
2. Go to **Settings** tab
3. Select **Branches** from the left sidebar
4. Click **Add rule** next to "Branch protection rules"

### Step 2: Configure Main Branch Protection

**Branch name pattern:** `main`

#### Required Status Checks
✅ **Enable:** "Require status checks to pass before merging"
- ✅ **Require branches to be up to date before merging**

**Required Checks:**
- `Security Validation / security-scan`
- `Security Validation / code-quality` 
- `Security Validation / frida-validation`
- `Security Validation / documentation-check`
- `Security Validation / approval-gate`

#### Pull Request Requirements
✅ **Enable:** "Require a pull request before merging"
- ✅ **Require approvals:** `2` (minimum)
- ✅ **Dismiss stale reviews when new commits are pushed**
- ✅ **Require review from code owners**
- ✅ **Restrict pushes that create pull requests**

#### Additional Restrictions
✅ **Enable:** "Restrict pushes to matching branches"
- **Allowed actors:** Repository administrators only

✅ **Enable:** "Do not allow bypassing the above settings"
- Applies to administrators as well

✅ **Enable:** "Allow force pushes" - ❌ **DISABLED**
✅ **Enable:** "Allow deletions" - ❌ **DISABLED**

### Step 3: Configure Development Branch Protection

**Branch name pattern:** `development`

#### Required Status Checks
✅ **Enable:** "Require status checks to pass before merging"
- ✅ **Require branches to be up to date before merging**

**Required Checks:**
- `Security Validation / security-scan`
- `Security Validation / code-quality`

#### Pull Request Requirements
✅ **Enable:** "Require a pull request before merging"
- ✅ **Require approvals:** `1` (minimum)
- ✅ **Dismiss stale reviews when new commits are pushed**

## 🎯 Approval Workflow

### Development Branch → Main Branch

1. **Create Pull Request** from `development` to `main`
2. **Automated Validation** runs (5 required checks)
3. **Security Review** by designated reviewers
4. **Code Review** by team members
5. **Minimum 2 Approvals** required
6. **Final Merge** only after all requirements met

### Feature Branch → Development Branch

1. **Create Pull Request** from feature branch to `development`
2. **Basic Validation** runs (2 required checks)
3. **Code Review** by team member
4. **Minimum 1 Approval** required
5. **Merge** to development branch

## 👥 Required Reviewers

### Security-Critical Reviews
- **Security Expert**: Must review security-related changes
- **Tool Maintainer**: Must review new tools and scripts
- **Documentation Lead**: Must review documentation changes

### Review Assignment
Reviews are automatically assigned based on:
- File paths modified (see CODEOWNERS)
- Type of changes made
- Security impact assessment

## 🚫 Merge Restrictions

### Prohibited Actions
- ❌ Direct pushes to `main` branch
- ❌ Force pushes to protected branches
- ❌ Deletion of protected branches
- ❌ Bypassing required status checks
- ❌ Merging without required approvals

### Emergency Procedures
For critical security fixes:
1. Create emergency hotfix branch
2. Follow expedited review process
3. Require immediate security team review
4. Document emergency procedures used

## 📋 Pre-Merge Checklist

### Automated Validation ✅
- [ ] Security scan passes (Bandit, Safety, Semgrep)
- [ ] Code quality checks pass (Black, flake8, mypy)
- [ ] Frida scripts syntax validated
- [ ] Documentation structure verified
- [ ] All tests pass

### Manual Review ✅
- [ ] Security implications assessed
- [ ] Code quality standards met
- [ ] Functionality verified
- [ ] Documentation accuracy confirmed
- [ ] No breaking changes (or properly documented)

### Approval Requirements ✅
- [ ] Minimum 2 approvals for main branch
- [ ] At least 1 security-focused reviewer
- [ ] Code owner approval (if applicable)
- [ ] All discussions resolved

## 🔧 Administrative Override

### When Override May Be Used
- Critical security patches
- Emergency bug fixes
- Infrastructure maintenance

### Override Process
1. Document reason for override
2. Get explicit approval from repository admin
3. Notify security team immediately
4. Schedule post-merge security review

## 📊 Monitoring and Compliance

### Metrics Tracked
- Merge frequency and timing
- Review turnaround time
- Security check failure rates
- Override usage patterns

### Regular Audits
- Monthly review of merge patterns
- Quarterly security assessment
- Annual policy review and updates

## 🎓 Training Requirements

### For Contributors
- Understanding of secure coding practices
- Familiarity with OWASP Mobile Top 10
- Knowledge of review requirements

### For Reviewers
- Security review training
- Tool safety assessment skills
- Code quality standards knowledge

## 📞 Support and Escalation

### For Questions
- Create issue with `question` label
- Contact repository maintainers
- Refer to documentation

### For Escalation
- Security concerns: Contact security team immediately
- Process disputes: Repository admin resolution
- Technical issues: DevOps team support

---

## 🚀 Implementation Commands

### Via GitHub CLI (if available)
```bash
# Enable branch protection for main
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["Security Validation / security-scan","Security Validation / code-quality","Security Validation / frida-validation","Security Validation / documentation-check","Security Validation / approval-gate"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":2,"dismiss_stale_reviews":true,"require_code_owner_reviews":true}' \
  --field restrictions=null

# Enable branch protection for development  
gh api repos/:owner/:repo/branches/development/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["Security Validation / security-scan","Security Validation / code-quality"]}' \
  --field required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \
  --field restrictions=null
```

### Manual Setup
Follow the web interface steps outlined above for complete configuration.

---

**Note:** These settings ensure that all code changes go through proper security validation and human review before being merged into the main branch, maintaining the integrity and security of the mobile penetration testing toolkit.

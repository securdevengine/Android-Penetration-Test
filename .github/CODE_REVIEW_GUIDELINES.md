# Code Review Guidelines - Mobile Security Toolkit

## 🎯 Overview

This document establishes comprehensive code review guidelines for the Android Reverse Engineering Toolkit, ensuring security, quality, and maintainability of all contributions.

## 🔒 Security-First Review Approach

### Critical Security Areas

#### 1. Credential and Secret Management
**What to Look For:**
- Hardcoded API keys, passwords, or tokens
- Exposed certificate data or private keys
- Database connection strings with credentials
- OAuth secrets or JWT signing keys

**Review Commands:**
```bash
# Search for potential secrets
grep -r -E "(password|secret|key|token)" --include="*.py" --include="*.js"
grep -r -E "['\"][A-Za-z0-9+/]{20,}['\"]" --include="*.py"
grep -r -E "sk_|pk_|Bearer |Basic " --include="*.py"
```

**Red Flags:**
❌ `API_KEY = "sk_abc123..."`
❌ `password = "admin123"`
❌ `JWT_SECRET = "mysecret"`

**Approved Patterns:**
✅ `API_KEY = os.environ.get('API_KEY')`
✅ `config = load_config_from_file()`
✅ `# TODO: Configure API key in config.json`

#### 2. Input Validation and Sanitization
**What to Look For:**
- User input processing without validation
- File path operations without sanitization
- Command injection vulnerabilities
- SQL injection possibilities

**Review Pattern:**
```python
# Vulnerable
def process_file(filename):
    os.system(f"cat {filename}")  # ❌ Command injection

# Secure
def process_file(filename):
    if not os.path.basename(filename) == filename:  # ✅ Path validation
        raise ValueError("Invalid filename")
    subprocess.run(["cat", filename], check=True)  # ✅ Safe execution
```

#### 3. Frida Script Security
**What to Look For:**
- Malicious JavaScript code
- Unintended application modifications
- Data exfiltration capabilities
- Privilege escalation attempts

**Review Checklist:**
- [ ] Script purpose clearly documented
- [ ] No network connections to external servers
- [ ] No file system modifications beyond logging
- [ ] Educational/defensive purpose only
- [ ] Proper error handling implemented

## 🧹 Code Quality Standards

### Python Code Standards

#### Style and Formatting
```python
# Required: PEP 8 compliance with 100-character line limit
# Tools: black, isort, flake8

# Good example
def analyze_apk(apk_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze APK file for security vulnerabilities.
    
    Args:
        apk_path: Path to the APK file to analyze
        output_dir: Optional output directory for results
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        FileNotFoundError: If APK file doesn't exist
        PermissionError: If insufficient permissions for analysis
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    
    # Implementation here
    return results
```

#### Error Handling
```python
# Required: Comprehensive error handling

# Good pattern
try:
    result = dangerous_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}")
    return None
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise
finally:
    cleanup_resources()

# Avoid
result = dangerous_operation()  # ❌ No error handling
```

#### Logging and Debugging
```python
# Required: Structured logging

import logging

logger = logging.getLogger(__name__)

def process_data(data):
    logger.info(f"Processing {len(data)} items")
    
    for item in data:
        try:
            result = process_item(item)
            logger.debug(f"Processed item {item['id']}: {result}")
        except Exception as e:
            logger.error(f"Failed to process item {item['id']}: {e}")
```

### JavaScript (Frida) Standards

#### Structure and Documentation
```javascript
// Required: Clear purpose and usage documentation

/**
 * Universal SSL Certificate Pinning Bypass
 * Purpose: Disable SSL certificate validation for security testing
 * Usage: frida -U -f com.target.app -l ssl_bypass.js --no-pause
 * Scope: Educational and authorized testing only
 */

console.log("[+] SSL Certificate Pinning Bypass loaded");

Java.perform(function() {
    console.log("[+] Starting SSL bypass implementations...");
    
    try {
        bypassSSLVerification();
        console.log("[+] SSL bypass setup complete");
    } catch (error) {
        console.log("[-] SSL bypass failed: " + error);
    }
});
```

## 👥 Review Process

### Review Assignment

#### Automatic Assignment (via CODEOWNERS)
- **Security-related files**: Security team members
- **Frida scripts**: Senior security researchers
- **Documentation**: Technical writers
- **Core tools**: Tool maintainers

#### Manual Assignment Guidelines
- **New contributors**: Assign experienced mentor
- **Complex changes**: Multiple reviewers required
- **Security tools**: Security expert mandatory
- **Breaking changes**: Architecture review needed

### Review Workflow

#### 1. Initial Review (Within 24 hours)
- [ ] Automated checks passing
- [ ] Security scan results reviewed
- [ ] PR template completed
- [ ] Change scope appropriate

#### 2. Technical Review (Within 48 hours)
- [ ] Code quality standards met
- [ ] Security implications assessed
- [ ] Functionality verified
- [ ] Documentation accuracy

#### 3. Security Review (Within 72 hours)
- [ ] No security vulnerabilities introduced
- [ ] Tools safe for intended purpose
- [ ] Follows ethical guidelines
- [ ] Proper disclaimers included

#### 4. Final Approval
- [ ] All feedback addressed
- [ ] Required approvals obtained
- [ ] Ready for merge

## 🔍 Specific Review Areas

### 1. Static Analysis Tools

**Review Focus:**
- Output parsing accuracy
- False positive handling
- Performance considerations
- Cross-platform compatibility

**Testing Requirements:**
```bash
# Test with various APK samples
python scripts/static_analysis/apk_analyzer.py sample1.apk
python scripts/static_analysis/apk_analyzer.py sample2.apk

# Verify output format
python -c "import json; json.load(open('results.json'))"
```

### 2. Dynamic Analysis Scripts

**Review Focus:**
- Frida hook effectiveness
- Target compatibility
- Error handling robustness
- Performance impact

**Testing Requirements:**
```bash
# Test with different Android versions
frida -U -f com.test.app -l hook_script.js --no-pause

# Verify cleanup on exit
# Check for memory leaks
# Test error conditions
```

### 3. OWASP Validation Tools

**Review Focus:**
- Coverage of all OWASP categories
- Accuracy of vulnerability detection
- Report quality and usefulness
- Performance with large APKs

**Validation Checklist:**
- [ ] All M1-M10 categories covered
- [ ] False positive rate acceptable
- [ ] Clear remediation guidance
- [ ] Scalable architecture

### 4. Documentation Updates

**Review Focus:**
- Technical accuracy
- Clarity and completeness
- Security warnings appropriate
- Examples functional

**Review Process:**
```bash
# Test all code examples
# Verify command syntax
# Check cross-references
# Validate security guidance
```

## ⚠️ Red Flags and Blockers

### Immediate Rejection Criteria

#### Security Issues
- ❌ Hardcoded credentials or secrets
- ❌ Malicious code or backdoors
- ❌ Unethical hacking tools
- ❌ Data exfiltration capabilities
- ❌ Privilege escalation exploits

#### Code Quality Issues
- ❌ No error handling
- ❌ Unclear variable names
- ❌ Missing documentation
- ❌ Obvious security vulnerabilities
- ❌ Non-functional code

#### Process Issues
- ❌ Incomplete PR template
- ❌ Failing automated checks
- ❌ No testing evidence
- ❌ Unclear change purpose
- ❌ Breaking changes without notice

### Warning Indicators

#### Needs Attention
- ⚠️ Complex logic without comments
- ⚠️ Performance concerns
- ⚠️ Unusual dependencies
- ⚠️ Limited test coverage
- ⚠️ Security implications unclear

## 📋 Review Checklist

### For All Pull Requests

#### Security Review
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented where needed
- [ ] Output sanitization for sensitive data
- [ ] Error messages don't leak information
- [ ] Tools are safe for intended purpose
- [ ] Ethical use guidelines followed

#### Code Quality
- [ ] Follows project coding standards
- [ ] Adequate error handling
- [ ] Clear variable and function names
- [ ] Appropriate comments and documentation
- [ ] No obvious performance issues

#### Functionality
- [ ] Code does what PR description claims
- [ ] Edge cases handled appropriately
- [ ] No regression in existing functionality
- [ ] Integrates well with existing codebase
- [ ] Backwards compatibility maintained

#### Testing
- [ ] Adequate test coverage
- [ ] Tests pass consistently
- [ ] Manual testing performed
- [ ] Cross-platform considerations addressed

#### Documentation
- [ ] Code is self-documenting or well-commented
- [ ] User-facing documentation updated
- [ ] API documentation current
- [ ] Security warnings appropriate

### For Security Tools

#### Additional Security Checks
- [ ] Tool purpose clearly documented
- [ ] Educational/defensive use only
- [ ] No malicious capabilities
- [ ] Proper disclaimers included
- [ ] Safe default configurations

#### Ethical Considerations
- [ ] Follows responsible disclosure principles
- [ ] Intended for authorized testing only
- [ ] No illegal activities enabled
- [ ] Clear usage guidelines provided

## 🎓 Reviewer Training

### Required Knowledge
- **Security Fundamentals**: OWASP Top 10, common vulnerabilities
- **Mobile Security**: Android security model, reverse engineering
- **Code Review**: Best practices, security patterns
- **Tools Understanding**: Frida, static analysis, OWASP tools

### Continuous Learning
- Regular security training updates
- Mobile security trend awareness
- Tool and technique evolution
- Community best practices

## 📊 Metrics and Improvement

### Review Quality Metrics
- Time to first review
- Number of review cycles
- Security issue detection rate
- Post-merge issue frequency

### Continuous Improvement
- Monthly review process assessment
- Quarterly guidelines updates
- Annual security training
- Community feedback integration

---

## 🚀 Quick Reference

### Emergency Review Process
For critical security fixes:
1. Tag PR with `security-critical`
2. Ping security team immediately
3. Expedited review within 4 hours
4. Post-merge security audit required

### Escalation Path
1. **Technical disputes**: Lead developer
2. **Security concerns**: Security team lead
3. **Process issues**: Repository maintainer
4. **External security**: Follow responsible disclosure

### Contact Information
- **Security Team**: @security-team
- **Tool Maintainers**: @tool-maintainers  
- **Documentation**: @doc-team
- **Emergency**: security@example.com

Remember: **Security and quality are everyone's responsibility** in this mobile security toolkit project.

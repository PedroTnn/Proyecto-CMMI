# OWASP Security in Authentication Service

This document outlines how the authentication service follows OWASP (Open Web Application Security Project) best practices to prevent common security vulnerabilities.

## Security Measures Implemented

### 1. Authentication

- Password hashing using bcrypt (secure one-way hashing with salt)
- Account lockout after multiple failed attempts
- Automatic unlocking after a timeout period
- Input validation for usernames and passwords

### 2. Input Validation

- Username format validation via regex pattern
- Password strength requirements
- Input sanitization to prevent injection attacks

### 3. Logging and Monitoring

- Secure logging of authentication attempts
- Logging includes IP address, username, and result
- No sensitive data (like passwords) in logs

### 4. Code Security Analysis

- Regular scanning with Bandit to detect:
  - Hardcoded credentials
  - SQL injection vulnerabilities
  - Command injection risks
  - Insecure cryptographic usage
  - Other security weaknesses

## OWASP Top 10 Addressed

1. **Broken Authentication**: Implemented account lockout and secure password hashing
2. **Injection**: Input validation and sanitization
3. **Sensitive Data Exposure**: No storage of plain text passwords
4. **Security Misconfiguration**: Regular security scanning with Bandit
5. **Logging & Monitoring**: Comprehensive logging of authentication attempts

## Running Security Checks

```bash
# Run Bandit security scanner
bandit -r app/ -c bandit.yml

# Run combined security and style checks
./run_qa.sh  # Linux/Mac
.\run_qa.bat # Windows
```

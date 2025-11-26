# 🤝 Contributing to LAN Reconnaissance Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🎯 Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Include system info (OS, Docker version)
- Provide reproduction steps
- Share relevant logs

### 2. Suggest Features
- Open an issue with the "enhancement" label
- Describe the use case
- Explain expected behavior
- Consider implementation complexity

### 3. Submit Code
- Fix bugs
- Add new scanning modules
- Create Nuclei templates
- Improve documentation
- Optimize performance

### 4. Improve Documentation
- Fix typos
- Add examples
- Create tutorials
- Translate content

## 🔧 Development Setup

### Fork and Clone
```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/bug-free-octo-pancake.git
cd bug-free-octo-pancake
```

### Create a Branch
```bash
git checkout -b feature/my-new-feature
# or
git checkout -b fix/bug-description
```

### Make Changes
```bash
# Edit files
# Test locally
./start.sh
```

### Commit Changes
```bash
git add .
git commit -m "feat: add new IoT device scanner"
# or
git commit -m "fix: resolve network interface detection issue"
```

### Push and Create PR
```bash
git push origin feature/my-new-feature
# Then create Pull Request on GitHub
```

## 📝 Commit Message Guidelines

Use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting)
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance tasks

Examples:
```
feat: add Raspberry Pi detection module
fix: correct network interface selection
docs: update USAGE.md with new examples
refactor: optimize nmap scanning parameters
```

## 🏗️ Adding a New Scanning Module

### 1. Create Module Directory
```bash
mkdir mymodule
cd mymodule
```

### 2. Create Dockerfile
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    your-tool \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY scan_script.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/scan_script.sh

WORKDIR /output
CMD ["/bin/bash"]
```

### 3. Create Scan Script
```bash
#!/bin/bash
OUTPUT_DIR=${1:-/output/mymodule}
mkdir -p "$OUTPUT_DIR"

echo "[*] Running custom scan..."
# Your scanning logic here

echo "[+] Custom scan complete."
```

### 4. Update docker-compose.yml
```yaml
  mymodule:
    build: ./mymodule
    container_name: recon-mymodule
    network_mode: host
    volumes:
      - ./output:/output
    command: ["/bin/bash", "-c", "sleep infinity"]
```

### 5. Add to Orchestrator
```python
def phase_8_custom_module(self):
    """Phase 8: Custom module"""
    self.log("PHASE 8: CUSTOM MODULE")
    self.run_container_command(
        "recon-mymodule",
        "/usr/local/bin/scan_script.sh /output/mymodule"
    )

# Add to run() method
def run(self):
    # ... existing phases ...
    self.phase_8_custom_module()
```

### 6. Test Your Module
```bash
# Build
docker-compose build mymodule

# Test standalone
docker-compose up -d mymodule
docker exec recon-mymodule /usr/local/bin/scan_script.sh /output/mymodule

# Test full workflow
./start.sh
```

### 7. Document Your Module
Update README.md with:
- Module purpose
- Required capabilities
- Expected output
- Usage examples

## 🧪 Testing Guidelines

### Before Submitting PR

1. **Test on real network**
```bash
./start.sh
./view-report.sh
```

2. **Test quick scan**
```bash
./quick-scan.sh
```

3. **Check for errors**
```bash
docker-compose logs | grep -i error
```

4. **Verify output structure**
```bash
ls -R output/
```

5. **Test cleanup**
```bash
./clean.sh
```

### Test Checklist
- [ ] Module builds successfully
- [ ] No runtime errors
- [ ] Output files created correctly
- [ ] Report includes new data
- [ ] Documentation updated
- [ ] No hardcoded credentials
- [ ] No security vulnerabilities introduced

## 📋 Code Style

### Shell Scripts
- Use `#!/bin/bash`
- Set `-e` for error handling
- Add comments for complex logic
- Use descriptive variable names
- Quote variables: `"$VAR"`

### Python
- Follow PEP 8
- Add docstrings
- Handle exceptions
- Use type hints where appropriate

### Dockerfiles
- Use official base images
- Combine RUN commands
- Clean up apt cache
- Pin versions for stability

## 🔐 Security Guidelines

### Never:
- Hardcode credentials
- Store sensitive data in repo
- Add backdoors or malicious code
- Bypass security controls
- Include proprietary/copyrighted code

### Always:
- Sanitize inputs
- Use secure defaults
- Handle errors gracefully
- Document security implications
- Test for common vulnerabilities

## 📚 Adding Nuclei Templates

### Template Structure
```yaml
id: unique-template-id

info:
  name: Template Name
  author: your-github-username
  severity: high
  description: What this template checks
  tags: iot,device-type,vulnerability-type

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      
      - type: word
        words:
          - "vulnerable_pattern"
    
    extractors:
      - type: regex
        regex:
          - 'data="([^"]+)"'
```

### Template Guidelines
- Use descriptive IDs
- Set appropriate severity
- Add multiple matchers for accuracy
- Include extractors for useful data
- Test on real devices
- Document false positive scenarios

## 🐛 Bug Report Template

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen.

**Environment**
- OS: [e.g. Ubuntu 22.04]
- Docker version: [e.g. 20.10.12]
- Docker Compose version: [e.g. 1.29.2]

**Logs**
```
Paste relevant logs here
```

**Additional context**
Any other relevant information.
```

## 🚀 Feature Request Template

```markdown
**Is your feature request related to a problem?**
Describe the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Other solutions you've thought about.

**Additional context**
Any other relevant information.
```

## 📖 Documentation Standards

### README Updates
- Keep formatting consistent
- Add to appropriate section
- Include examples
- Update table of contents if needed

### Code Comments
```python
def complex_function(param):
    """
    Brief description of what function does.
    
    Args:
        param: Description of parameter
    
    Returns:
        Description of return value
    """
    # Explain complex logic
    pass
```

## ✅ Pull Request Checklist

Before submitting PR:
- [ ] Code follows project style
- [ ] All tests pass
- [ ] New tests added (if applicable)
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No merge conflicts
- [ ] Changes are focused and minimal
- [ ] Security implications considered

## 🎉 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Appreciated in the community!

## ❓ Questions?

- Open a Discussion on GitHub
- Check existing Issues
- Review documentation
- Ask in Pull Request comments

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to the LAN Reconnaissance Framework! 🙏**

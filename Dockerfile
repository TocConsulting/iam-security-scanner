FROM python:3.11-slim-bookworm

LABEL maintainer="Toc Consulting <tarek@tocconsulting.fr>"
LABEL description="AWS IAM security scanner with multi-framework compliance mapping for CIS, PCI-DSS, HIPAA, SOC 2, ISO, GDPR, and NIST"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY iam_security_scanner/ ./iam_security_scanner/

# Install the package (all dependencies have binary wheels for Python 3.11)
RUN pip install --no-cache-dir .

# Create output directory.
# NOTE: the container runs as root so the documented credential mount
# (-v ~/.aws:/root/.aws:ro) and env-var credentials both work. A non-root
# user cannot read a host ~/.aws/credentials file (uid mismatch + 0600
# perms), which silently broke `--profile` based runs.
RUN mkdir -p /app/output

# Default entrypoint
ENTRYPOINT ["iam-security-scanner"]

# Default command (show help)
CMD ["--help"]

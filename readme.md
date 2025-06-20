# Domain Tools MCP Server

![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Model Context Protocol (MCP) server for comprehensive domain analysis: WHOIS, DNS records, and DNS health checks.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Deployment](#deployment)
7. [Usage](#usage)
8. [API Reference](#api-reference)
9. [Configuration](#configuration)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)
12. [Support and Contribution](#support-and-contribution)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)

---

## Overview

The Domain Tools MCP Server is a Model Context Protocol (MCP) server that provides comprehensive domain analysis capabilities. It offers tools for WHOIS lookups, DNS record queries, and DNS health checking to help you analyze and monitor domain configurations.

---

## Features

- **WHOIS Information**: Get detailed domain registration data.
- **DNS Records**: Query various DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA).
- **DNS Health Checks**: Identify common DNS configuration issues.
- **Comprehensive Analysis**: Complete domain assessment in one tool.

---

## Project Structure

```
.
├── domain_tools_server.py   # Main server implementation
├── requirements.txt
├── .gitignore
├── README.md
└── ...
```

---

## Requirements

- Python 3.13+ (recommended)
- pip (Python package installer)
- Internet connection for DNS/WHOIS queries

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/deshabhishek007/domain-tools-mcp-server.git
cd domain-tools-mcp-server
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv domain-tools-env
source domain-tools-env/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python -c "import mcp, dns.resolver, whois; print('All dependencies installed successfully!')"
```

---

## Deployment

### Local Development

```bash
python domain_tools_server.py
```

Or make it executable:
```bash
chmod +x domain_tools_server.py
./domain_tools_server.py
```

### Production Deployment

#### Using systemd (Linux)

1. Create a service file `/etc/systemd/system/domain-tools-mcp.service`:

    ```ini
    [Unit]
    Description=Domain Tools MCP Server
    After=network.target

    [Service]
    Type=simple
    User=your-username
    WorkingDirectory=/path/to/your/project
    Environment=PATH=/path/to/your/project/domain-tools-env/bin
    ExecStart=/path/to/your/project/domain-tools-env/bin/python domain_tools_server.py
    Restart=always
    RestartSec=10

    [Install]
    WantedBy=multi-user.target
    ```

2. Enable and start the service:

    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable domain-tools-mcp.service
    sudo systemctl start domain-tools-mcp.service
    ```

#### Using Docker

1. Create a `Dockerfile`:

    ```dockerfile
    FROM python:3.13-slim
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    COPY domain_tools_server.py .
    EXPOSE 8080
    CMD ["python", "domain_tools_server.py"]
    ```

2. Build and run:

    ```bash
    docker build -t domain-tools-mcp .
    docker run -p 8080:8080 domain-tools-mcp
    ```

---

## Usage

### MCP Client Integration

The server implements the Model Context Protocol and can be integrated with any MCP-compatible client.

**Example MCP Client Configuration:**
```json
{
  "servers": {
    "domain-tools": {
      "command": "python",
      "args": ["/path/to/domain_tools_server.py"],
      "env": {}
    }
  }
}
```

---

## API Reference

### Available Tools

#### 1. WHOIS Lookup

- **Parameters:**  
  - `domain` (string, required): Domain name to lookup

- **Example Request:**
    ```json
    {
      "tool": "whois_lookup",
      "arguments": {
        "domain": "example.com"
      }
    }
    ```

- **Sample Output:**
    ```json
    {
      "domain": "example.com",
      "registrar": "Example Registrar Inc.",
      "creation_date": "2023-01-15T00:00:00Z",
      "expiration_date": "2025-01-15T00:00:00Z",
      "updated_date": "2024-01-15T00:00:00Z",
      "status": ["clientTransferProhibited"],
      "name_servers": ["ns1.example.com", "ns2.example.com"],
      "days_until_expiry": 215
    }
    ```

#### 2. DNS Records Query

- **Parameters:**  
  - `domain` (string, required): Domain name to query  
  - `record_types` (array, optional): DNS record types to query (default: `["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]`)

- **Example Request:**
    ```json
    {
      "tool": "dns_records",
      "arguments": {
        "domain": "example.com",
        "record_types": ["A", "MX", "NS"]
      }
    }
    ```

#### 3. DNS Health Check

- **Parameters:**  
  - `domain` (string, required): Domain name to analyze

- **Example Request:**
    ```json
    {
      "tool": "dns_health_check",
      "arguments": {
        "domain": "example.com"
      }
    }
    ```

#### 4. Complete Domain Analysis

- **Parameters:**  
  - `domain` (string, required): Domain name to analyze

- **Example Request:**
    ```json
    {
      "tool": "domain_analysis",
      "arguments": {
        "domain": "example.com"
      }
    }
    ```

### Tool Schemas

Each tool follows a JSON schema for input. See the code for full details.

### Response Format

All tools return responses in the following format:
```json
[
  {
    "type": "text",
    "text": "Tool-specific formatted output"
  }
]
```

---

## Configuration

### DNS Resolver

You can customize the DNS resolver in the server code:

```python
self.dns_resolver.nameservers = ['8.8.8.8', '8.8.4.4']
self.dns_resolver.timeout = 10
self.dns_resolver.lifetime = 30
```

### Environment Variables

You can configure the server using environment variables:

```bash
export DNS_TIMEOUT=10
export DNS_LIFETIME=30
export WHOIS_TIMEOUT=30
export SERVER_NAME="domain-tools"
export SERVER_VERSION="1.0.0"
```

---

## Troubleshooting

### Common Issues

- **Import Errors:**  
  Run `pip install --upgrade mcp dnspython python-whois pydantic`.

- **DNS Resolution Failures:**  
  - Check internet connectivity.
  - Try different DNS servers.
  - Increase timeout values.

- **WHOIS Lookup Failures:**  
  - Some domains may have restricted WHOIS access.
  - Rate limiting may be in effect.

- **Permission Errors:**  
  - Run with appropriate permissions.
  - Use non-privileged ports for testing.

### Debug Mode

Enable debug logging by adding this to your server:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Security Considerations

- **Input Validation:** Always validate domain inputs.
- **Rate Limiting:** Implement rate limiting to prevent abuse.
- **Network Security:** Use secure DNS resolvers.
- **Logging:** Log all queries for audit purposes.
- **Access Control:** Implement authentication if needed.

---

## Support and Contribution

- For issues, feature requests, or contributions, please open an issue or pull request on GitHub.
- Contributions are welcome! Please review the troubleshooting section and provide detailed error messages and logs if reporting bugs.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [dnspython](https://www.dnspython.org/)
- [python-whois](https://pypi.org/project/python-whois/)
- [pydantic](https://docs.pydantic.dev/)
- [MCP (Model Context Protocol)](https://github.com/microsoft/mcp)

---

## Author

- Abhishek Deshpande([@deshabhishek007](https://github.com/deshabhishek007))

---

## Notes

- This server is intended for use as a backend service or as part of a larger system that communicates using the MCP protocol.
- For more information on MCP, see the [official documentation](https://github.com/microsoft/mcp).

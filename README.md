
## Overview

> This report provides an overview of the Python backend application and its dependencies, including their versions and package URLs.



### Application Details

- **Name:** python-backend
- **Version:** 1.0.0
- **Package URL:** [pkg:pypi/python-backend@1.0.0](https://pypi.org/project/python-backend/1.0.0/)

### Dependencies

The following dependencies were found for the Python backend application:

1. **asgiref**
   - **Version:** 3.6.0
   - **Package URL:** [pkg:pypi/asgiref@3.6.0](https://pypi.org/project/asgiref/3.6.0/)
   - **No vulnerabilities found**

2. **build**
   - **Version:** 1.0.3
   - **Package URL:** [pkg:pypi/build@1.0.3](https://pypi.org/project/build/1.0.3/)
   - **No vulnerabilities found**

3. **cachecontrol**
   - **Version:** 0.13.1
   - **Package URL:** [pkg:pypi/cachecontrol@0.13.1](https://pypi.org/project/cachecontrol/0.13.1/)
   - **No vulnerabilities found**

4. **certifi**
   - **Version:** 2022.12.7
   - **Package URL:** [pkg:pypi/certifi@2022.12.7](https://pypi.org/project/certifi/2022.12.7/)
   - **Vulnerabilities:**
     - [CVE-2023-37920] CWE-345: Insufficient Verification of Data Authenticity (CVSS score: 9.8)
     - **Description:** Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi prior to version 2023.07.22 recognizes "e-Tugra" root certificates. e-Tugra's root certificates were subject to an investigation prompted by reporting of security issues in their systems. Certifi 2023.07.22 removes root certificates from "e-Tugra" from the root store. Sonatype's research suggests that this CVE's details differ from those defined at NVD. See [here](https://example-link-for-details.com) for details.

# dify-ee-k8s-security-scanner
One script to control Trivy Scan against Dify EE hosted in k8s.

## Prerequisites
- You have a running Dify EE in k8s.
- You installed kubectl, Trivy, Docker, AWS CLI(optional) in your local computer and can access control panel of k8s.

## Key Features 
- Scan all dify ee images including plugin images
- Outputs:
     - Raw log
     - Human-friendly html report
     - LLM-friendly xml report

## Usage
```
bash dify_security_scan.sh --help 
>>
==================================================
🔐 Kubernetes Security Scan Script
==================================================

Kubernetes Security Scan Script

Usage: dify_security_scan.sh [options]

Options:
    -n, --namespace <namespace>  Specify the Kubernetes namespace to scan (default: dify)
    --skip-unstructured         Skip scanning all images containing 'unstructured'
    -h, --help                  Show this help message

Examples:
    dify_security_scan.sh                                    # Scan all images in 'dify' namespace
    dify_security_scan.sh -n your_namespace                     # Scan certian namespace
    dify_security_scan.sh --namespace test --skip-unstructured  # Scan test namespace, skip unstructured images
    dify_security_scan.sh --skip-unstructured                # Scan dify namespace, skip unstructured images

Features:
    - Scan Kubernetes configuration security issues in specified namespace
    - Scan container image vulnerabilities
    - Generate detailed HTML security report
```


## Future works

- Support other registory (currently on AWS ECR is supported)
- Compelete xml generation and LLM query / next step suggestion
- Better html template and information sharing
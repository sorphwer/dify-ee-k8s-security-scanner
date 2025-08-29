#!/bin/bash

# Kubernetes Security Scan Script
# Function: Scan Kubernetes namespace for configuration issues and container image vulnerabilities, generate HTML report

set -e  # Exit on error

# Global variables
SKIP_UNSTRUCTURED=false
NAMESPACE="dify"
TIMESTAMP=""

# Generate timestamp
generate_timestamp() {
    TIMESTAMP=$(date '+%Y-%m-%d-%H-%M-%S')
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-unstructured)
                SKIP_UNSTRUCTURED=true
                log_info "Skip-unstructured mode enabled: will skip all images containing 'unstructured'"
                shift
                ;;
            -n|--namespace)
                if [[ -n "$2" ]] && [[ "$2" != -* ]]; then
                    NAMESPACE="$2"
                    log_info "Target namespace set to: $NAMESPACE"
                    shift 2
                else
                    log_error "--namespace/-n parameter requires a namespace name"
                    show_help
                    exit 1
                fi
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown parameter: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Show help information
show_help() {
    cat << EOF
Kubernetes Security Scan Script

Usage: $0 [options]

Options:
    -n, --namespace <namespace>  Specify the Kubernetes namespace to scan (default: dify)
    --skip-unstructured         Skip scanning all images containing 'unstructured'
    -h, --help                  Show this help message

Examples:
    $0                                    # Scan all images in dify namespace
    $0 -n production                      # Scan production namespace
    $0 --namespace test --skip-unstructured  # Scan test namespace, skip unstructured images
    $0 --skip-unstructured                # Scan dify namespace, skip unstructured images

Features:
    - Scan Kubernetes configuration security issues in specified namespace
    - Scan container image vulnerabilities
    - Generate detailed HTML security report
EOF
}

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check required tools
check_requirements() {
    log_info "Checking required tools..."
    
    local missing_tools=()
    
    if ! command -v trivy &> /dev/null; then
        missing_tools+=("trivy")
    fi
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warning "jq not installed, JSON validation will be skipped"
    fi
    
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not installed, private image scanning may fail"
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "The following required tools are not installed: ${missing_tools[*]}"
        log_error "Please install the missing tools and run again"
        exit 1
    fi
    
    log_success "All required tools are ready"
}

# Check Kubernetes connection
check_k8s_connection() {
    log_info "Checking Kubernetes connection..."
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Unable to connect to Kubernetes cluster"
        exit 1
    fi
    
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace '$NAMESPACE' does not exist"
        exit 1
    fi
    
    log_success "Kubernetes connection is normal, namespace '$NAMESPACE' exists"
}

# Scan Kubernetes configuration
scan_k8s_misconfig() {
    log_info "Scanning Kubernetes configuration issues in namespace '$NAMESPACE'..."
    
    local misconfig_file="${NAMESPACE}-misconfig-scan-${TIMESTAMP}.json"
    if trivy k8s --include-namespaces "$NAMESPACE" --scanners misconfig --format json --timeout 15m -o "$misconfig_file"; then
        log_success "Kubernetes configuration scan completed"
    else
        log_warning "Kubernetes configuration scan failed, will continue with empty configuration"
        echo '{"Results":[]}' > "$misconfig_file"
    fi
}

# Get Trivy version
get_trivy_version() {
    if command -v trivy &> /dev/null; then
        trivy --version | head -n 1 | cut -d' ' -f2 2>/dev/null || echo "unknown"
    else
        echo "not installed"
    fi
}

# Get Dify version information from Helm
get_dify_version() {
    local chart_version="unknown"
    local app_version="unknown"
    
    if command -v helm &> /dev/null; then
        # Try to get Dify release information from the specified namespace
        if kubectl get namespace "$NAMESPACE" &> /dev/null; then
            # Get Dify release info using helm list
            local dify_release=$(helm list -n "$NAMESPACE" --output json 2>/dev/null | jq -r '.[] | select(.name == "dify") | .chart' 2>/dev/null)
            local dify_app_version=$(helm list -n "$NAMESPACE" --output json 2>/dev/null | jq -r '.[] | select(.name == "dify") | .app_version' 2>/dev/null)
            
            if [[ -n "$dify_release" ]] && [[ "$dify_release" != "null" ]]; then
                # Extract chart version from chart name (e.g., "dify-3.4.1" -> "3.4.1")
                chart_version=$(echo "$dify_release" | sed 's/^dify-//')
            fi
            
            if [[ -n "$dify_app_version" ]] && [[ "$dify_app_version" != "null" ]]; then
                app_version="$dify_app_version"
            fi
        fi
    fi
    
    echo "$chart_version|$app_version"
}

# Get image list
get_container_images() {
    log_info "Getting container images in namespace '$NAMESPACE'..."
    
    # Fix image list extraction to ensure one image per line
    kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort | uniq | grep -v '^$' > "${NAMESPACE}-images-all.txt"
    
    local total_image_count=$(wc -l < "${NAMESPACE}-images-all.txt")
    log_info "Found ${total_image_count} different container images in total"
    
    # If skip-unstructured option is enabled, filter images containing 'unstructured'
    if [[ "$SKIP_UNSTRUCTURED" == "true" ]]; then
        log_info "Filtering images containing 'unstructured'..."
        
        # Create filtered image lists
        > "${NAMESPACE}-images.txt"
        > "${NAMESPACE}-skipped-images.txt"
        
        while IFS= read -r image; do
            if [[ -n "$image" ]]; then
                if [[ "$image" == *"unstructured"* ]]; then
                    echo "$image" >> "${NAMESPACE}-skipped-images.txt"
                else
                    echo "$image" >> "${NAMESPACE}-images.txt"
                fi
            fi
        done < "${NAMESPACE}-images-all.txt"
        
        local skipped_count=$(wc -l < "${NAMESPACE}-skipped-images.txt" 2>/dev/null || echo "0")
        local scan_count=$(wc -l < "${NAMESPACE}-images.txt")
        
        log_warning "Skipped ${skipped_count} images containing 'unstructured'"
        if [[ $skipped_count -gt 0 ]]; then
            log_info "Skipped image list:"
            while IFS= read -r image; do
                if [[ -n "$image" ]]; then
                    echo "  - [SKIPPED] $image"
                fi
            done < "${NAMESPACE}-skipped-images.txt"
        fi
        
        log_success "Will scan ${scan_count} images (skipped ${skipped_count})"
    else
        # No filtering, use all images
        cp "${NAMESPACE}-images-all.txt" "${NAMESPACE}-images.txt"
        local scan_count=$(wc -l < "${NAMESPACE}-images.txt")
        log_success "Found ${scan_count} different container images"
    fi
    
    # Display scan image list
    log_info "Images to scan:"
    while IFS= read -r image; do
        if [[ -n "$image" ]]; then
            echo "  - $image"
        fi
    done < "${NAMESPACE}-images.txt"
}

# ECR login helper: login to all ECR registries present in a given image list file
# Returns success/failure status for ECR authentication
ecr_login_from_file() {
    local images_file="$1"
    local ecr_success=false
    
    if [[ ! -f "$images_file" ]]; then
        log_info "No image file found, skipping ECR authentication"
        return 1
    fi
    
    # Check prerequisites
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not installed, ECR authentication not possible"
        return 1
    fi
    
    if ! command -v aws &> /dev/null; then
        log_warning "AWS CLI not installed, skipping ECR authentication"
        return 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &>/dev/null; then
        log_warning "Docker daemon not running, ECR authentication not possible"
        return 1
    fi
    
    # Check AWS credentials configuration
    log_info "Checking AWS credentials configuration..."
    if ! aws sts get-caller-identity &>/dev/null; then
        log_error "AWS credentials not configured or invalid"
        log_error "Please configure AWS credentials using one of the following methods:"
        log_error "  1. aws configure"
        log_error "  2. Set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        log_error "  3. Use IAM roles (for EC2 instances)"
        log_error "  4. Use AWS profiles: export AWS_PROFILE=your-profile"
        return 1
    fi
    
    local aws_identity=$(aws sts get-caller-identity --output text --query 'Arn' 2>/dev/null || echo "Unknown")
    local aws_account_id=$(aws sts get-caller-identity --output text --query 'Account' 2>/dev/null || echo "Unknown")
    local aws_region=$(aws configure get region 2>/dev/null || echo "Unknown")
    
    log_info "AWS authentication successful as: $aws_identity"
    log_info "AWS Account ID: $aws_account_id"
    log_info "Default AWS Region: $aws_region"
    
    # Extract unique ECR registries (portable, without mapfile)
    local registries
    registries=$(grep -oE '[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com' "$images_file" 2>/dev/null | sort -u || true)
    if [[ -z "$registries" ]]; then
        log_info "No ECR registries found in image list"
        return 0
    fi
    
    log_info "Found ECR registries, attempting authentication..."
    log_info "ECR registries to authenticate:"
    echo "$registries" | while IFS= read -r reg; do
        [[ -n "$reg" ]] && echo "  - $reg"
    done
    
    local total_registries=0
    local successful_registries=0
    
    echo "$registries" | while IFS= read -r reg; do
        [[ -n "$reg" ]] || continue
        total_registries=$((total_registries + 1))
        
        local region
        region=$(sed -E 's/^[0-9]{12}\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/\1/' <<< "$reg")
        if [[ -z "$region" ]]; then
            log_warning "Could not extract region from ECR registry: $reg"
            continue
        fi
        
        log_info "Attempting ECR login for region: $region, registry: $reg"
        
        # Try AWS ECR authentication using the working command format
        local auth_success=false
        
        # Use the proven working command: aws ecr get-login-password | docker login
        # Check which timeout command is available
        local timeout_cmd=""
        if command -v timeout &> /dev/null; then
            timeout_cmd="timeout 60"
        elif command -v gtimeout &> /dev/null; then
            timeout_cmd="gtimeout 60"
        fi

        # Build the ECR login command with appropriate timeout
        local ecr_login_cmd
        if [[ -n "$timeout_cmd" ]]; then
            ecr_login_cmd="$timeout_cmd aws ecr get-login-password --region \"$region\" | $timeout_cmd docker login --username AWS --password-stdin \"$reg\""
        else
            ecr_login_cmd="aws ecr get-login-password --region \"$region\" | docker login --username AWS --password-stdin \"$reg\""
        fi

        if eval "$ecr_login_cmd >/dev/null 2>&1"; then
            log_success "ECR authentication successful: $reg"
            successful_registries=$((successful_registries + 1))
            auth_success=true
        else
            log_warning "ECR authentication failed: $reg"
            log_warning "Failed command: aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $reg"
            log_warning "Please check:"
            log_warning "  1. AWS credentials have ECR permissions"
            log_warning "  2. Region '$region' is correct and accessible"
            log_warning "  3. ECR registry '$reg' exists and you have access"
            log_warning "Try manually: aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $reg"
        fi
        
        # Store authentication status for this registry
        if [[ "$auth_success" == "true" ]]; then
            echo "$reg" >> "/tmp/ecr-authenticated-registries.txt"
        else
            echo "$reg" >> "/tmp/ecr-failed-registries.txt"
        fi
    done
    
    # Read results from temp files (subshell limitation workaround)
    local auth_count=0
    local failed_count=0
    
    if [[ -f "/tmp/ecr-authenticated-registries.txt" ]]; then
        auth_count=$(wc -l < "/tmp/ecr-authenticated-registries.txt")
        rm -f "/tmp/ecr-authenticated-registries.txt"
    fi
    
    if [[ -f "/tmp/ecr-failed-registries.txt" ]]; then
        failed_count=$(wc -l < "/tmp/ecr-failed-registries.txt")
        rm -f "/tmp/ecr-failed-registries.txt"
    fi
    
    if [[ $auth_count -gt 0 ]]; then
        log_success "ECR authentication completed: $auth_count successful, $failed_count failed"
        return 0
    else
        log_warning "ECR authentication failed for all registries"
        return 1
    fi
}

# 已移除：与镜像体积相关的所有函数与交互

# Scan container image vulnerabilities
scan_container_images() {
    log_info "Scanning container image vulnerabilities..."
    
    # Use the full image list directly
    local scan_list="${NAMESPACE}-images.txt"
    
    # Create image scan results directory
    mkdir -p image_scans
    
    # Read image list and scan
    local scan_count=0
    local success_count=0
    
    # ECR login is completed in the main process
    # Image classification is also completed in the main process
    
    # Scan single image function
    scan_single_image() {
        local image="$1"
        local scan_count="$2"
        
        log_info "Scanning image ($scan_count): $image"
        
        # Generate safe filename
        local safe_filename=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/_/g')
        local output_file="image_scans/scan_${safe_filename}.json"
        
        # Check if it's an ECR image and handle authentication
        if [[ "$image" =~ dkr\.ecr\..*\.amazonaws\.com ]]; then
            if ! docker info &>/dev/null; then
                log_warning "Skipping ECR image (Docker daemon not running): $image"
                echo '{"Results":[], "SchemaVersion": 2, "ArtifactName": "'$image'", "ArtifactType": "container_image"}' > "$output_file"
                return 1
            fi
            
            # Test if we can access the ECR image by trying a quick manifest check
            local registry=$(echo "$image" | grep -oE '[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com')

            # Check which timeout command is available for manifest inspection
            local manifest_cmd
            if command -v timeout &> /dev/null; then
                manifest_cmd="timeout 10 docker manifest inspect \"$image\""
            elif command -v gtimeout &> /dev/null; then
                manifest_cmd="gtimeout 10 docker manifest inspect \"$image\""
            else
                manifest_cmd="docker manifest inspect \"$image\""
            fi

            if ! eval "$manifest_cmd &>/dev/null"; then
                log_warning "Skipping ECR image (authentication failed or image not accessible): $image"
                echo '{"Results":[], "SchemaVersion": 2, "ArtifactName": "'$image'", "ArtifactType": "container_image"}' > "$output_file"
                return 1
            fi
        fi
        
        # Scan image with retry mechanism and detailed error handling
        local retry_count=0
        local max_retries=2
        local scan_success=false
        
        while [[ $retry_count -lt $max_retries ]] && [[ $scan_success == false ]]; do
            if [[ $retry_count -gt 0 ]]; then
                log_warning "Retrying image scan: $image (attempt $((retry_count + 1)))"
            fi
            
            # Try different scanning strategies
            # Use fixed timeout (removed dynamic timeout based on image size)
            local scan_timeout="120"
            local trivy_timeout="2m"
            
            local scan_command
            if command -v timeout &> /dev/null; then
                scan_command="timeout ${scan_timeout} trivy image --format json --severity HIGH,MEDIUM,CRITICAL --timeout ${trivy_timeout} --no-progress --quiet"
            elif command -v gtimeout &> /dev/null; then
                scan_command="gtimeout ${scan_timeout} trivy image --format json --severity HIGH,MEDIUM,CRITICAL --timeout ${trivy_timeout} --no-progress --quiet"
            else
                scan_command="trivy image --format json --severity HIGH,MEDIUM,CRITICAL --timeout ${trivy_timeout} --no-progress --quiet"
            fi
            
            if $scan_command "$image" > "$output_file" 2>/dev/null; then
                # Check if output file is valid
                if [[ -s "$output_file" ]]; then
                    if command -v jq &> /dev/null; then
                        if jq empty "$output_file" 2>/dev/null; then
                            log_success "Image scan completed: $image"
                            scan_success=true
                            return 0
                        fi
                    else
                        # No jq, simple file content check
                        if grep -q "Results" "$output_file" 2>/dev/null; then
                            log_success "Image scan completed: $image"
                            scan_success=true
                            return 0
                        fi
                    fi
                fi
                log_warning "Image scan output invalid: $image"
                retry_count=$((retry_count + 1))
            else
                log_warning "Image scan failed: $image"
                retry_count=$((retry_count + 1))
            fi
            
            if [[ $scan_success == false ]] && [[ $retry_count -lt $max_retries ]]; then
                sleep 1
            fi
        done
        
        # If all retries fail, create empty result
        log_warning "Image scan finally failed: $image"
        echo '{"Results":[]}' > "$output_file"
        return 1
    }
    
    # Scan public images first
    if [[ -s "${NAMESPACE}-public-images.txt" ]]; then
        log_info "Starting to scan public images..."
        while IFS= read -r image; do
            if [[ -n "$image" ]]; then
                scan_count=$((scan_count + 1))
                if scan_single_image "$image" "$scan_count"; then
                    success_count=$((success_count + 1))
                fi
            fi
        done < "${NAMESPACE}-public-images.txt"
    fi
    
    # Then scan remaining images (private images)
    log_info "Scanning other images..."
    while IFS= read -r image; do
        if [[ -n "$image" ]]; then
            # Skip already scanned public images
            if ! grep -q "^$image$" "${NAMESPACE}-public-images.txt" 2>/dev/null; then
                scan_count=$((scan_count + 1))
                if scan_single_image "$image" "$scan_count"; then
                    success_count=$((success_count + 1))
                fi
            fi
        fi
    done < "$scan_list"
    
    log_success "Image scanning completed, successfully scanned ${success_count}/${scan_count} images"
    
    # Display scan summary
    if [[ $success_count -gt 0 ]]; then
        log_info "Successfully scanned images will be included in the report"
    else
        log_warning "All image scans failed, report will only contain configuration scan results"
    fi
}

# Process JSON and count vulnerabilities
count_vulnerabilities() {
    local json_file="$1"
    local severity="$2"
    
    if [[ ! -f "$json_file" ]]; then
        echo "0"
        return
    fi
    
    # Count vulnerabilities with specific severity
    local count=0
    if command -v jq &> /dev/null; then
        count=$(jq -r --arg sev "$severity" '
            [.Results[]?.Vulnerabilities[]? | select(.Severity == $sev)] | length
        ' "$json_file" 2>/dev/null || echo "0")
    else
        # Fallback to grep if jq not available
        count=$(grep -o "\"Severity\":\"$severity\"" "$json_file" 2>/dev/null | wc -l || echo "0")
    fi
    
    echo "$count"
}

# Count misconfigurations
count_misconfigurations() {
    local json_file="$1"
    
    if [[ ! -f "$json_file" ]]; then
        echo "0"
        return
    fi
    
    local count=0
    if command -v jq &> /dev/null; then
        count=$(jq -r '[.Results[]?.Misconfigurations[]?] | length' "$json_file" 2>/dev/null || echo "0")
    else
        # Fallback to grep
        count=$(grep -o '"Misconfigurations"' "$json_file" 2>/dev/null | wc -l || echo "0")
    fi
    
    echo "$count"
}

# Escape HTML special characters
escape_html() {
    local text="$1"
    echo "$text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g'
}

# Escape XML special characters
escape_xml() {
    local text="$1"
    echo "$text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&apos;/g'
}

# Generate HTML misconfig content
generate_misconfig_html() {
    local misconfig_file="$1"
    local content=""
    
    if [[ ! -f "$misconfig_file" ]]; then
        echo '<div class="no-issues">✅ No Kubernetes configuration security issues found</div>'
        return
    fi
    
    if command -v jq &> /dev/null; then
        # Use jq to parse JSON
        local has_issues=false
        while IFS= read -r result; do
            local target=$(echo "$result" | jq -r '.Target // "Unknown Resource"')
            local misconfigs=$(echo "$result" | jq -c '.Misconfigurations[]?' 2>/dev/null)
            
            if [[ -n "$misconfigs" ]]; then
                has_issues=true
                content+="<h3>📋 Resource: $(escape_html "$target")</h3>"
                
                while IFS= read -r misconfig; do
                    local severity=$(echo "$misconfig" | jq -r '.Severity // "UNKNOWN"')
                    local title=$(echo "$misconfig" | jq -r '.Title // "Unknown Configuration Issue"')
                    local description=$(echo "$misconfig" | jq -r '.Description // "No description"')
                    
                    local desc_preview="${description:0:100}"
                    if [[ ${#description} -gt 100 ]]; then
                        desc_preview+="..."
                    fi
                    
                    content+="
                    <div class=\"misconfiguration\">
                        <div class=\"vuln-header\">
                            <span class=\"severity ${severity}\">${severity}</span>
                            <span class=\"vuln-title\">$(escape_html "$title")</span>
                        </div>
                        <details class=\"description-details\">
                            <summary class=\"description-summary\">
                                <strong>Description:</strong> $(escape_html "$desc_preview")
                            </summary>
                            <div class=\"description-full\">$(escape_html "$description")</div>
                        </details>
                    </div>"
                done <<< "$misconfigs"
            fi
        done < <(jq -c '.Results[]?' "$misconfig_file" 2>/dev/null)
        
        if [[ "$has_issues" == false ]]; then
            content='<div class="no-issues">✅ No Kubernetes configuration security issues found</div>'
        fi
    else
        # Fallback without jq
        content='<div class="no-issues">⚠️ Unable to parse configuration scan results (jq not installed)</div>'
    fi
    
    echo "$content"
}

# Generate HTML vulnerability content for images
generate_image_vulns_html() {
    local content=""
    local image_count=0
    
    if [[ ! -d "image_scans" ]]; then
        echo '<div class="no-issues">✅ No container images scanned or no vulnerabilities found</div>'
        return
    fi
    
    for scan_file in image_scans/scan_*.json; do
        [[ -f "$scan_file" ]] || continue
        image_count=$((image_count + 1))
        
        if command -v jq &> /dev/null; then
            local image_name=$(jq -r '.Results[0].Target // "Unknown Image"' "$scan_file" 2>/dev/null)
            
            # Count vulnerabilities by severity
            local critical_count=$(count_vulnerabilities "$scan_file" "CRITICAL")
            local high_count=$(count_vulnerabilities "$scan_file" "HIGH")
            local medium_count=$(count_vulnerabilities "$scan_file" "MEDIUM")
            local low_count=$(count_vulnerabilities "$scan_file" "LOW")
            
            content+="
                <details>
                    <summary>
                        <div class=\"image-title\">
                            <h3>🐳 Image: <span class='image-name'>$(escape_html "$image_name")</span></h3>
                        </div>
                        <div class=\"vuln-summary\">
                            <span class=\"summary-item critical\">Critical: ${critical_count}</span>
                            <span class=\"summary-item high\">High: ${high_count}</span>
                            <span class=\"summary-item medium\">Medium: ${medium_count}</span>
                            <span class=\"summary-item low\">Low: ${low_count}</span>
                        </div>
                    </summary>
                    <div class=\"details-content\">"
            
            # Generate vulnerability details by severity
            local has_vulns=false
            for severity in "CRITICAL" "HIGH" "MEDIUM" "LOW"; do
                local severity_label=""
                case $severity in
                    CRITICAL) severity_label="🔴 Critical Vulnerabilities" ;;
                    HIGH) severity_label="🟠 High Vulnerabilities" ;;
                    MEDIUM) severity_label="🟡 Medium Vulnerabilities" ;;
                    LOW) severity_label="🟢 Low Vulnerabilities" ;;
                esac
                
                local vulns=$(jq -c --arg sev "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $sev)]' "$scan_file" 2>/dev/null)
                local vuln_count=$(echo "$vulns" | jq 'length' 2>/dev/null || echo "0")
                
                if [[ "$vuln_count" -gt 0 ]]; then
                    has_vulns=true
                    content+="<h4 class=\"severity-section\">${severity_label} (${vuln_count} items)</h4>"
                    
                    # Use for loop instead of while to avoid subshell issues
                    local vuln_array
                    if command -v mapfile &> /dev/null; then
                        mapfile -t vuln_array < <(echo "$vulns" | jq -c '.[]' 2>/dev/null)
                    else
                        # Fallback for systems without mapfile (like macOS)
                        vuln_array=()
                        while IFS= read -r line; do
                            [[ -n "$line" ]] && vuln_array+=("$line")
                        done < <(echo "$vulns" | jq -c '.[]' 2>/dev/null)
                    fi
                    
                    for vuln in "${vuln_array[@]}"; do
                        [[ -n "$vuln" ]] || continue
                        
                        local vuln_id=$(echo "$vuln" | jq -r '.VulnerabilityID // "Unknown ID"')
                        local pkg_name=$(echo "$vuln" | jq -r '.PkgName // "Unknown Package"')
                        local installed_version=$(echo "$vuln" | jq -r '.InstalledVersion // "Unknown Version"')
                        local fixed_version=$(echo "$vuln" | jq -r '.FixedVersion // "None"')
                        local title=$(echo "$vuln" | jq -r '.Title // .VulnerabilityID')
                        local description=$(echo "$vuln" | jq -r '.Description // "No description"')
                        
                        local desc_preview="${description:0:100}"
                        if [[ ${#description} -gt 100 ]]; then
                            desc_preview+="..."
                        fi
                        
                        # Convert severity to lowercase for CSS class
                        local severity_lower=$(echo "$severity" | tr '[:upper:]' '[:lower:]')

                        content+="
                            <div class=\"vulnerability ${severity_lower}\">
                                <div class=\"vuln-header\">
                                    <span class=\"severity ${severity}\">${severity}</span>
                                    <span class=\"vuln-id\">$(escape_html "$vuln_id")</span>
                                    <span class=\"vuln-title\">$(escape_html "$title")</span>
                                </div>
                                <div class=\"vuln-details\">
                                    <div class=\"vuln-detail\"><strong>Package:</strong> $(escape_html "$pkg_name")</div>
                                    <div class=\"vuln-detail\"><strong>Current Version:</strong> $(escape_html "$installed_version")</div>
                                    <div class=\"vuln-detail\"><strong>Fixed Version:</strong> $(escape_html "$fixed_version")</div>
                                </div>
                                <details class=\"description-details\">
                                    <summary class=\"description-summary\">
                                        <strong>Description:</strong> $(escape_html "$desc_preview")
                                    </summary>
                                    <div class=\"description-full\">$(escape_html "$description")</div>
                                </details>
                            </div>"
                    done
                fi
            done
            
            if [[ "$has_vulns" == false ]]; then
                content+='<div class="no-issues">✅ No vulnerabilities found in this image</div>'
            fi
            
            content+="</div></details>"
        fi
    done
    
    if [[ $image_count -eq 0 ]]; then
        content='<div class="no-issues">✅ No container images scanned or no vulnerabilities found</div>'
    fi
    
    echo "$content"
}

# Generate XML misconfig content
generate_misconfig_xml() {
    local misconfig_file="$1"
    local content=""
    
    if [[ ! -f "$misconfig_file" ]]; then
        echo "        <message>No Kubernetes configuration security issues found</message>"
        return
    fi
    
    if command -v jq &> /dev/null; then
        while IFS= read -r result; do
            local target=$(echo "$result" | jq -r '.Target // "Unknown Resource"')
            local misconfigs=$(echo "$result" | jq -c '.Misconfigurations[]?' 2>/dev/null)
            
            if [[ -n "$misconfigs" ]]; then
                content+="
        <resource>
            <name>$(escape_xml "$target")</name>
            <misconfigurations>"
                
                while IFS= read -r misconfig; do
                    local severity=$(echo "$misconfig" | jq -r '.Severity // "UNKNOWN"')
                    local title=$(echo "$misconfig" | jq -r '.Title // "Unknown Configuration Issue"')
                    local description=$(echo "$misconfig" | jq -r '.Description // "No description"')
                    
                    content+="
                <misconfiguration>
                    <severity>${severity}</severity>
                    <title>$(escape_xml "$title")</title>
                    <description>$(escape_xml "$description")</description>
                </misconfiguration>"
                done <<< "$misconfigs"
                
                content+="
            </misconfigurations>
        </resource>"
            fi
        done < <(jq -c '.Results[]?' "$misconfig_file" 2>/dev/null)
        
        if [[ -z "$content" ]]; then
            content="        <message>No Kubernetes configuration security issues found</message>"
        fi
    else
        content="        <message>Unable to parse configuration scan results (jq not installed)</message>"
    fi
    
    echo "$content"
}

# Generate XML vulnerability content for images
generate_image_vulns_xml() {
    local content=""
    local image_count=0
    
    if [[ ! -d "image_scans" ]]; then
        echo "        <message>No container images scanned or no vulnerabilities found</message>"
        return
    fi
    
    for scan_file in image_scans/scan_*.json; do
        [[ -f "$scan_file" ]] || continue
        image_count=$((image_count + 1))
        
        if command -v jq &> /dev/null; then
            local image_name=$(jq -r '.Results[0].Target // "Unknown Image"' "$scan_file" 2>/dev/null)
            
            # Count vulnerabilities by severity
            local critical_count=$(count_vulnerabilities "$scan_file" "CRITICAL")
            local high_count=$(count_vulnerabilities "$scan_file" "HIGH")
            local medium_count=$(count_vulnerabilities "$scan_file" "MEDIUM")
            local low_count=$(count_vulnerabilities "$scan_file" "LOW")
            
            content+="
        <image>
            <name>$(escape_xml "$image_name")</name>
            <vulnerability-summary>
                <critical>${critical_count}</critical>
                <high>${high_count}</high>
                <medium>${medium_count}</medium>
                <low>${low_count}</low>
            </vulnerability-summary>
            <vulnerabilities>"
            
            local has_vulns=false
            for severity in "CRITICAL" "HIGH" "MEDIUM" "LOW"; do
                local vulns=$(jq -c --arg sev "$severity" '[.Results[]?.Vulnerabilities[]? | select(.Severity == $sev)]' "$scan_file" 2>/dev/null)
                local vuln_count=$(echo "$vulns" | jq 'length' 2>/dev/null || echo "0")
                
                if [[ "$vuln_count" -gt 0 ]]; then
                    has_vulns=true
                    content+="
                <severity-group level=\"${severity}\">"
                    
                    echo "$vulns" | jq -c '.[]' | while IFS= read -r vuln; do
                        local vuln_id=$(echo "$vuln" | jq -r '.VulnerabilityID // "Unknown ID"')
                        local pkg_name=$(echo "$vuln" | jq -r '.PkgName // "Unknown Package"')
                        local installed_version=$(echo "$vuln" | jq -r '.InstalledVersion // "Unknown Version"')
                        local fixed_version=$(echo "$vuln" | jq -r '.FixedVersion // "None"')
                        local title=$(echo "$vuln" | jq -r '.Title // .VulnerabilityID')
                        local description=$(echo "$vuln" | jq -r '.Description // "No description"')
                        
                        content+="
                    <vulnerability>
                        <id>$(escape_xml "$vuln_id")</id>
                        <package>$(escape_xml "$pkg_name")</package>
                        <current-version>$(escape_xml "$installed_version")</current-version>
                        <fixed-version>$(escape_xml "$fixed_version")</fixed-version>
                        <title>$(escape_xml "$title")</title>
                        <description>$(escape_xml "$description")</description>
                    </vulnerability>"
                    done
                    
                    content+="
                </severity-group>"
                fi
            done
            
            if [[ "$has_vulns" == false ]]; then
                content+="
                <message>No vulnerabilities found in this image</message>"
            fi
            
            content+="
            </vulnerabilities>
        </image>"
        fi
    done
    
    if [[ $image_count -eq 0 ]]; then
        content="        <message>No container images scanned or no vulnerabilities found</message>"
    fi
    
    echo "$content"
}

# Generate full HTML report
generate_html_report() {
    log_info "Generating HTML security report..."
    
    local misconfig_file="${NAMESPACE}-misconfig-scan-${TIMESTAMP}.json"
    local template_file="lib/report-template.html"
    
    if [[ ! -f "$template_file" ]]; then
        log_error "HTML template file not found: $template_file"
        exit 1
    fi
    
    # Count statistics
    local total_misconfigs=$(count_misconfigurations "$misconfig_file")
    local total_vulns=0
    local critical_vulns=0
    local high_vulns=0
    local medium_vulns=0
    local low_vulns=0
    local image_count=0
    
    # Count vulnerabilities from all image scans
    if [[ -d "image_scans" ]]; then
        for scan_file in image_scans/scan_*.json; do
            [[ -f "$scan_file" ]] || continue
            image_count=$((image_count + 1))
            
            local crit=$(count_vulnerabilities "$scan_file" "CRITICAL")
            local high=$(count_vulnerabilities "$scan_file" "HIGH")
            local med=$(count_vulnerabilities "$scan_file" "MEDIUM")
            local low=$(count_vulnerabilities "$scan_file" "LOW")
            
            critical_vulns=$((critical_vulns + crit))
            high_vulns=$((high_vulns + high))
            medium_vulns=$((medium_vulns + med))
            low_vulns=$((low_vulns + low))
            total_vulns=$((total_vulns + crit + high + med + low))
        done
    fi
    
    # Get scan time
    local scan_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Generate content sections
    local misconfig_content=$(generate_misconfig_html "$misconfig_file")
    local image_vulns_content=$(generate_image_vulns_html)
    
    # Generate report from template
    local output_file="${NAMESPACE}-security-scan-report-${TIMESTAMP}.html"

    # Copy template to output file first
    cp "$template_file" "$output_file"

    # Get Dify version information
    local dify_versions=$(get_dify_version)
    local dify_chart_version=$(echo "$dify_versions" | cut -d'|' -f1)
    local dify_app_version=$(echo "$dify_versions" | cut -d'|' -f2)

    # Replace placeholders using sed (safer for multiline content)
    sed -i.bak \
        -e "s|{{SCAN_TIME}}|$scan_time|g" \
        -e "s|{{TRIVY_VERSION}}|$(get_trivy_version)|g" \
        -e "s|{{NAMESPACE}}|$NAMESPACE|g" \
        -e "s|{{DIFY_CHART_VERSION}}|$dify_chart_version|g" \
        -e "s|{{DIFY_APP_VERSION}}|$dify_app_version|g" \
        -e "s|{{CRITICAL_VULNS}}|$critical_vulns|g" \
        -e "s|{{HIGH_VULNS}}|$high_vulns|g" \
        -e "s|{{MEDIUM_VULNS}}|$medium_vulns|g" \
        -e "s|{{LOW_VULNS}}|$low_vulns|g" \
        -e "s|{{TOTAL_VULNS}}|$total_vulns|g" \
        -e "s|{{TOTAL_MISCONFIGS}}|$total_misconfigs|g" \
        -e "s|{{IMAGE_COUNT}}|$image_count|g" \
        "$output_file"

    # Handle multiline content separately to avoid sed delimiter issues
    # Create temporary files for multiline content
    local temp_misconfig_file="/tmp/misconfig_content_$$.txt"
    local temp_vulns_file="/tmp/vulns_content_$$.txt"

    echo "$misconfig_content" > "$temp_misconfig_file"
    echo "$image_vulns_content" > "$temp_vulns_file"

    # Replace multiline placeholders using pure bash/sed method
    log_info "Processing HTML template with multiline content..."
    
    # Use sed to replace multiline placeholders (improved compatibility)
    # First handle MISCONFIG_CONTENT
    if sed -i.bak -e "/{{MISCONFIG_CONTENT}}/{" -e "r $temp_misconfig_file" -e "d" -e "}" "$output_file" 2>/dev/null; then
        log_info "MISCONFIG_CONTENT placeholder replaced successfully"
    else
        log_warning "Failed to replace MISCONFIG_CONTENT placeholder with sed, trying alternative method"
        # Alternative method using awk
        if command -v awk &> /dev/null; then
            awk -v replacement_file="$temp_misconfig_file" '
                /{{MISCONFIG_CONTENT}}/ {
                    while ((getline line < replacement_file) > 0) {
                        print line
                    }
                    close(replacement_file)
                    next
                }
                { print }
            ' "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
            log_info "MISCONFIG_CONTENT replacement completed using awk"
        fi
    fi
    
    # Then handle IMAGE_VULNS_CONTENT  
    if sed -i.bak -e "/{{IMAGE_VULNS_CONTENT}}/{" -e "r $temp_vulns_file" -e "d" -e "}" "$output_file" 2>/dev/null; then
        log_info "IMAGE_VULNS_CONTENT placeholder replaced successfully"
    else
        log_warning "Failed to replace IMAGE_VULNS_CONTENT placeholder with sed, trying alternative method"
        # Alternative method using awk
        if command -v awk &> /dev/null; then
            awk -v replacement_file="$temp_vulns_file" '
                /{{IMAGE_VULNS_CONTENT}}/ {
                    while ((getline line < replacement_file) > 0) {
                        print line
                    }
                    close(replacement_file)
                    next
                }
                { print }
            ' "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
            log_info "IMAGE_VULNS_CONTENT replacement completed using awk"
        fi
    fi

    # Clean up temporary files
    rm -f "$temp_misconfig_file" "$temp_vulns_file"
    rm -f "${output_file}.bak"
    
    log_success "HTML report generated successfully: $output_file"
    
    # Generate XML report
    generate_xml_report
}

# Generate full XML report
generate_xml_report() {
    log_info "Generating XML report for LLM..."
    
    local misconfig_file="${NAMESPACE}-misconfig-scan-${TIMESTAMP}.json"
    local template_file="lib/report-template.xml"
    
    if [[ ! -f "$template_file" ]]; then
        log_error "XML template file not found: $template_file"
        exit 1
    fi
    
    # Count statistics (same as HTML)
    local total_misconfigs=$(count_misconfigurations "$misconfig_file")
    local total_vulns=0
    local critical_vulns=0
    local high_vulns=0
    local medium_vulns=0
    local low_vulns=0
    local image_count=0
    
    # Count vulnerabilities from all image scans
    if [[ -d "image_scans" ]]; then
        for scan_file in image_scans/scan_*.json; do
            [[ -f "$scan_file" ]] || continue
            image_count=$((image_count + 1))
            
            local crit=$(count_vulnerabilities "$scan_file" "CRITICAL")
            local high=$(count_vulnerabilities "$scan_file" "HIGH")
            local med=$(count_vulnerabilities "$scan_file" "MEDIUM")
            local low=$(count_vulnerabilities "$scan_file" "LOW")
            
            critical_vulns=$((critical_vulns + crit))
            high_vulns=$((high_vulns + high))
            medium_vulns=$((medium_vulns + med))
            low_vulns=$((low_vulns + low))
            total_vulns=$((total_vulns + crit + high + med + low))
        done
    fi
    
    # Get scan time
    local scan_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Generate content sections
    local misconfig_xml_content=$(generate_misconfig_xml "$misconfig_file")
    local image_vulns_xml_content=$(generate_image_vulns_xml)
    
    # Generate report from template
    local output_file="dify-security-scan-report-for-llm-${TIMESTAMP}.xml"

    # Copy template to output file first
    cp "$template_file" "$output_file"

    # Get Dify version information
    local dify_versions=$(get_dify_version)
    local dify_chart_version=$(echo "$dify_versions" | cut -d'|' -f1)
    local dify_app_version=$(echo "$dify_versions" | cut -d'|' -f2)

    # Replace simple placeholders using sed
    sed -i.bak \
        -e "s|{{SCAN_TIME}}|$scan_time|g" \
        -e "s|{{TRIVY_VERSION}}|$(get_trivy_version)|g" \
        -e "s|{{NAMESPACE}}|$NAMESPACE|g" \
        -e "s|{{DIFY_CHART_VERSION}}|$dify_chart_version|g" \
        -e "s|{{DIFY_APP_VERSION}}|$dify_app_version|g" \
        -e "s|{{IMAGE_COUNT}}|$image_count|g" \
        -e "s|{{TOTAL_VULNS}}|$total_vulns|g" \
        -e "s|{{CRITICAL_VULNS}}|$critical_vulns|g" \
        -e "s|{{HIGH_VULNS}}|$high_vulns|g" \
        -e "s|{{MEDIUM_VULNS}}|$medium_vulns|g" \
        -e "s|{{LOW_VULNS}}|$low_vulns|g" \
        -e "s|{{TOTAL_MISCONFIGS}}|$total_misconfigs|g" \
        "$output_file"

    # Handle multiline XML content separately
    # Create temporary files for multiline content
    local temp_misconfig_xml_file="/tmp/misconfig_xml_content_$$.txt"
    local temp_vulns_xml_file="/tmp/vulns_xml_content_$$.txt"

    echo "$misconfig_xml_content" > "$temp_misconfig_xml_file"
    echo "$image_vulns_xml_content" > "$temp_vulns_xml_file"

    # Replace multiline placeholders using pure bash/sed method
    log_info "Processing XML template with multiline content..."
    
    # Use sed to replace multiline placeholders (improved compatibility)
    # First handle MISCONFIG_XML_CONTENT
    if sed -i.bak -e "/{{MISCONFIG_XML_CONTENT}}/{" -e "r $temp_misconfig_xml_file" -e "d" -e "}" "$output_file" 2>/dev/null; then
        log_info "MISCONFIG_XML_CONTENT placeholder replaced successfully"
    else
        log_warning "Failed to replace MISCONFIG_XML_CONTENT placeholder with sed, trying alternative method"
        # Alternative method using awk
        if command -v awk &> /dev/null; then
            awk -v replacement_file="$temp_misconfig_xml_file" '
                /{{MISCONFIG_XML_CONTENT}}/ {
                    while ((getline line < replacement_file) > 0) {
                        print line
                    }
                    close(replacement_file)
                    next
                }
                { print }
            ' "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
            log_info "MISCONFIG_XML_CONTENT replacement completed using awk"
        fi
    fi
    
    # Then handle IMAGE_VULNS_XML_CONTENT
    if sed -i.bak -e "/{{IMAGE_VULNS_XML_CONTENT}}/{" -e "r $temp_vulns_xml_file" -e "d" -e "}" "$output_file" 2>/dev/null; then
        log_info "IMAGE_VULNS_XML_CONTENT placeholder replaced successfully"
    else
        log_warning "Failed to replace IMAGE_VULNS_XML_CONTENT placeholder with sed, trying alternative method"
        # Alternative method using awk
        if command -v awk &> /dev/null; then
            awk -v replacement_file="$temp_vulns_xml_file" '
                /{{IMAGE_VULNS_XML_CONTENT}}/ {
                    while ((getline line < replacement_file) > 0) {
                        print line
                    }
                    close(replacement_file)
                    next
                }
                { print }
            ' "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
            log_info "IMAGE_VULNS_XML_CONTENT replacement completed using awk"
        fi
    fi

    # Clean up temporary files
    rm -f "$temp_misconfig_xml_file" "$temp_vulns_xml_file"
    rm -f "${output_file}.bak"
    
    log_success "XML report for LLM generated: $output_file"
}

# Clean up temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    
    # Keep main result files, clean up temporary files
    if [[ -d "image_scans" ]]; then
        rm -rf image_scans
    fi
    
    if [[ -f "${NAMESPACE}-images.txt" ]]; then
        rm -f "${NAMESPACE}-images.txt"
    fi
    
    if [[ -f "${NAMESPACE}-images-all.txt" ]]; then
        rm -f "${NAMESPACE}-images-all.txt"
    fi
    
    if [[ -f "${NAMESPACE}-public-images.txt" ]]; then
        rm -f "${NAMESPACE}-public-images.txt"
    fi
    
    if [[ -f "${NAMESPACE}-ecr-images.txt" ]]; then
        rm -f "${NAMESPACE}-ecr-images.txt"
    fi
    
    if [[ -f "${NAMESPACE}-other-images.txt" ]]; then
        rm -f "${NAMESPACE}-other-images.txt"
    fi
    
    if [[ -f "${NAMESPACE}-skipped-images.txt" ]]; then
        rm -f "${NAMESPACE}-skipped-images.txt"
    fi
    
    if [[ -f "images_large.txt" ]]; then
        rm -f images_large.txt
    fi
    
    if [[ -f "images_small_or_unknown.txt" ]]; then
        rm -f images_small_or_unknown.txt
    fi
    
    if [[ -f "${NAMESPACE}-images.to-scan.txt" ]]; then
        rm -f "${NAMESPACE}-images.to-scan.txt"
    fi
    
    log_success "Temporary files cleaned up successfully"
}

# Display report information
show_report_info() {
    log_success "=== Scan Completed ==="
    echo
    log_info "Generated files:"
    echo "  📄 ${NAMESPACE}-security-scan-report-${TIMESTAMP}.html - Complete HTML security report"
    echo "  📄 dify-security-scan-report-for-llm-${TIMESTAMP}.xml - XML report for LLM processing"
    echo "  📄 ${NAMESPACE}-misconfig-scan-${TIMESTAMP}.json - Kubernetes configuration scan raw data"
    echo
    log_info "View report:"
    echo "  Open in browser: file://$(pwd)/${NAMESPACE}-security-scan-report-${TIMESTAMP}.html"
    echo "  Or run: open ${NAMESPACE}-security-scan-report-${TIMESTAMP}.html"
    echo
}

# Main function
main() {
    echo "=================================================="
    echo "🔐 Kubernetes Security Scan Script"
    echo "=================================================="
    echo
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Generate timestamp for file naming
    generate_timestamp
    
    # Check environment
    check_requirements
    check_k8s_connection
    
    echo
    log_info "Starting security scan for namespace '$NAMESPACE'..."
    
    # Get image list and classify images by type
    get_container_images
    
    # Create image classification lists for scanning strategy
    log_info "Classifying images by type for scanning strategy..."
    
    # Use the main image list for classification
    local scan_list="${NAMESPACE}-images.txt"
    
    # Public images (prioritize these)
    grep -E "^(nginx|ubuntu|quay\.io|langgenius)" "$scan_list" > "${NAMESPACE}-public-images.txt" 2>/dev/null || touch "${NAMESPACE}-public-images.txt"
    
    # ECR images (need authentication) - Updated regex to match any ECR registry format
    grep -E "dkr\.ecr\..*\.amazonaws\.com" "$scan_list" > "${NAMESPACE}-ecr-images.txt" 2>/dev/null || touch "${NAMESPACE}-ecr-images.txt"
    
    # Other private images
    grep -v -E "^(nginx|ubuntu|quay\.io|langgenius)" "$scan_list" | grep -v -E "dkr\.ecr\..*\.amazonaws\.com" > "${NAMESPACE}-other-images.txt" 2>/dev/null || touch "${NAMESPACE}-other-images.txt"
    
    local public_count=$(wc -l < "${NAMESPACE}-public-images.txt")
    local ecr_count=$(wc -l < "${NAMESPACE}-ecr-images.txt")
    local other_count=$(wc -l < "${NAMESPACE}-other-images.txt")
    
    log_info "Image classification:"
    log_info "  - Public images: $public_count"
    log_info "  - ECR images: $ecr_count"
    log_info "  - Other images: $other_count"
    
    # Check if ECR authentication is needed and attempt login
    if [[ $ecr_count -gt 0 ]]; then
        log_info "ECR images detected, attempting authentication..."
        if ecr_login_from_file "${NAMESPACE}-images.txt"; then
            log_success "ECR authentication successful, can scan ECR images"
        else
            log_warning "ECR authentication failed, ECR images will be skipped during scanning"
        fi
    else
        log_info "No ECR images found, skipping ECR authentication"
    fi
    
    # Execute scans
    scan_k8s_misconfig
    scan_container_images
    
    # Generate report
    generate_html_report
    
    # Clean up and display results
    cleanup
    show_report_info
    
    log_success "Dify security scan completed!"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

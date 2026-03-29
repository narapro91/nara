# Secure Serverless Asset Proxy

**Architecture:** CloudFront → Lambda Function URL → Private S3 Bucket

A production-grade, serverless asset delivery system built with Go, AWS Lambda
(container image), CloudFront, and Infrastructure-as-Code via CloudFormation.

---

## Folder Structure

```
.
├── .github/
│   └── workflows/
│       ├── build.yml          # Push → build image → push to ECR → trigger deploy
│       └── deploy.yml         # Dispatch → deploy/update CloudFormation stack
├── infrastructure/
│   └── template.yaml          # Single CloudFormation template (all resources)
├── lambda/
│   ├── Dockerfile             # Multi-stage build → Lambda provided:al2023
│   ├── go.mod
│   ├── go.sum
│   └── main.go                # Lambda handler (Go, AWS SDK v2)
└── README.md
```

---

## Security Design

| Control | Implementation |
|---|---|
| No public S3 access | `PublicAccessBlockConfiguration` + bucket policy `DenyNonTLS` |
| Least-privilege IAM | Lambda role has `s3:GetObject` only on the asset bucket |
| Immutable image tags | ECR repository `IMAGETAG_MUTABILITY=IMMUTABLE`; images tagged with Git SHA |
| CloudFront → Lambda secret | `X-Origin-Verify` shared secret; Lambda returns `403` if header is absent or wrong |
| HTTPS only | CloudFront `redirect-to-https`; origin `OriginProtocolPolicy: https-only`; S3 bucket policy denies non-TLS |
| Security headers | HSTS, X-Content-Type-Options, X-Frame-Options, XSS-Protection, Referrer-Policy, Permissions-Policy |
| OIDC authentication | GitHub Actions uses OIDC — no long-lived AWS keys stored as secrets |

---

## Prerequisites

### AWS resources required before first deploy

1. **OIDC identity provider** for GitHub Actions in your AWS account  
   See: <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services>

2. **IAM role** that GitHub Actions can assume via OIDC.  
   Minimum permissions the role needs:
   - `ecr:*` (create/push repositories)
   - `cloudformation:*`
   - `lambda:*`
   - `s3:*`
   - `iam:*` (to create the Lambda execution role)
   - `cloudfront:*`

### GitHub repository secrets

| Secret | Description |
|---|---|
| `AWS_ROLE_ARN` | ARN of the OIDC-enabled IAM role (e.g. `arn:aws:iam::123456789012:role/github-actions-role`) |
| `ORIGIN_VERIFY_TOKEN` | A random string ≥ 32 characters shared between CloudFront and Lambda |

Generate a token:
```bash
openssl rand -base64 32
```

---

## Deployment Steps

### 1. First-time bootstrap

```bash
# Clone the repository
git clone https://github.com/narapro91/nara.git
cd nara

# Set your AWS region and account (adjust as needed)
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### 2. Push code to trigger the CI/CD pipeline

```bash
git add .
git commit -m "feat: initial asset proxy deployment"
git push origin main
```

This triggers **build.yml** which:
1. Creates the ECR repository if it does not exist (with `scanOnPush=true` and immutable tags)
2. Builds the Docker image and tags it with the Git commit SHA
3. Pushes the image to ECR
4. Triggers **deploy.yml** with the new image URI

**deploy.yml** then:
1. Runs `aws cloudformation deploy` to create or update the stack
2. Prints all stack outputs (CloudFront domain, bucket name, Lambda URL)

### 3. Upload an asset to the S3 bucket

```bash
BUCKET=$(aws cloudformation describe-stacks \
  --stack-name asset-proxy \
  --query "Stacks[0].Outputs[?OutputKey=='AssetBucketName'].OutputValue" \
  --output text)

aws s3 cp ./my-image.png "s3://${BUCKET}/images/my-image.png"
```

### 4. Test via CloudFront

```bash
CF_DOMAIN=$(aws cloudformation describe-stacks \
  --stack-name asset-proxy \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontDomain'].OutputValue" \
  --output text)

# Fetch an asset by key
curl -o output.png "https://${CF_DOMAIN}/?key=images/my-image.png"

# Expected: HTTP 200, body is the image bytes
# For text files:
curl "https://${CF_DOMAIN}/?key=docs/readme.txt"
```

### 5. Verify direct Lambda access is blocked

```bash
LAMBDA_URL=$(aws cloudformation describe-stacks \
  --stack-name asset-proxy \
  --query "Stacks[0].Outputs[?OutputKey=='LambdaFunctionUrl'].OutputValue" \
  --output text)

# Should return 403 Forbidden (missing X-Origin-Verify header)
curl -v "${LAMBDA_URL}?key=images/my-image.png"
```

---

## Manual Deploy (without CI/CD)

```bash
# Build and push the image
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_TAG=$(git rev-parse --short HEAD)
IMAGE_URI="${ECR_REGISTRY}/asset-proxy:${IMAGE_TAG}"

aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

docker build --platform linux/amd64 -t "$IMAGE_URI" ./lambda
docker push "$IMAGE_URI"

# Deploy the CloudFormation stack
aws cloudformation deploy \
  --template-file infrastructure/template.yaml \
  --stack-name asset-proxy \
  --parameter-overrides \
      ImageUri="$IMAGE_URI" \
      OriginVerifyToken="$(openssl rand -base64 32)" \
      Environment=prod \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$AWS_REGION"
```

---

## How It Works

```
User
 │
 │  HTTPS GET /?key=path/to/file
 ▼
CloudFront  ──── security headers ────────────────────────────────────────┐
 │  cache miss                                                             │
 │  adds X-Origin-Verify: <secret> header                                 │
 ▼                                                                         │
Lambda Function URL (HTTPS)                                                │
 │  verifies X-Origin-Verify header → 403 if missing                      │
 │  reads "key" query parameter                                            │
 │  calls s3:GetObject on private bucket                                   │
 │  base64-encodes body (supports binary assets)                           │
 │  returns Content-Type, Cache-Control, ETag headers                      │
 ▼                                                                         │
Private S3 Bucket (no public access)                                       │
                                                                           │
CloudFront caches response, applies security headers ◄─────────────────────┘
 │
 ▼
User receives asset bytes
```

---

## CloudFormation Resources

| Resource | Type | Purpose |
|---|---|---|
| `AssetBucket` | `AWS::S3::Bucket` | Private asset storage with versioning and SSE |
| `AssetBucketPolicy` | `AWS::S3::BucketPolicy` | Deny non-TLS; allow Lambda role only |
| `LambdaExecutionRole` | `AWS::IAM::Role` | `s3:GetObject` only + CloudWatch Logs |
| `AssetProxyFunction` | `AWS::Lambda::Function` | Container image Lambda |
| `AssetProxyFunctionUrl` | `AWS::Lambda::Url` | Public HTTPS endpoint for Lambda |
| `FunctionUrlPublicPermission` | `AWS::Lambda::Permission` | Allow invocation via Function URL |
| `SecurityHeadersPolicy` | `AWS::CloudFront::ResponseHeadersPolicy` | HSTS, X-Frame-Options, etc. |
| `AssetCachePolicy` | `AWS::CloudFront::CachePolicy` | Cache on `key` query parameter |
| `AssetOriginRequestPolicy` | `AWS::CloudFront::OriginRequestPolicy` | Forward `key` to origin |
| `CloudFrontDistribution` | `AWS::CloudFront::Distribution` | Public CDN entry point |

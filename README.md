# API Key Rotation Lambda Function

This AWS Lambda function performs **API key rotation** integrated with AWS Secrets Manager and API Gateway. It follows the AWS Secrets Manager **rotation process** (`createSecret`, `setSecret`, `testSecret`, `finishSecret`) to rotate API keys securely.

The function ensures the seamless creation, testing, and replacement of API keys, cleaning up old keys once rotation is complete.

---

## Code Walkthrough

### 1. Import Dependencies
```python
import boto3
import json
import logging
```
- **boto3**: AWS SDK for Python to interact with AWS services like Secrets Manager and API Gateway.
- **json**: To handle JSON serialization and deserialization.
- **logging**: For logging information, warnings, and errors during execution.

---

### 2. Setup Logging
```python
logger = logging.getLogger()
logger.setLevel(logging.INFO)
```
- **logger**: Configures logging to capture events at `INFO` level and above.

---

### 3. Initialize AWS Clients
```python
secrets_manager_client = boto3.client('secretsmanager')
apigateway_client = boto3.client('apigateway')
```
- **secrets_manager_client**: Interface to interact with AWS Secrets Manager.
- **apigateway_client**: Interface to interact with AWS API Gateway.

---

### 4. Lambda Handler
```python
def lambda_handler(event, context):
    step = event['Step']
    token = event['ClientRequestToken']
    secret_arn = event['SecretId']
```
- **event**: Input payload containing details of the rotation step (`Step`), client token, and secret ARN.
- **context**: AWS Lambda runtime context (not explicitly used here).
- **step**: Current step of the rotation (`createSecret`, `setSecret`, `testSecret`, `finishSecret`).

---

### 5. Handle Rotation Steps
```python
    try:
        if step == 'createSecret':
            create_secret(secret_arn, token)
        elif step == 'setSecret':
            set_secret(secret_arn, token)
        elif step == 'testSecret':
            test_secret(secret_arn, token)
        elif step == 'finishSecret':
            finish_secret(secret_arn, token)
        else:
            raise ValueError(f"Unknown step: {step}")
```
- Routes execution based on the **rotation step**.
- Throws an error if an unknown step is provided.

### 6. Log Errors
```python
    except Exception as e:
        logger.error(f"Error in step {step} for token {token} and secret {secret_arn}: {e}")
        raise
```
- Logs any exceptions encountered and re-raises the error to stop execution.

---

### 7. Retrieve Tags for Secret
```python
def get_tags_from_secret(secret_arn):
    response = secrets_manager_client.describe_secret(SecretId=secret_arn)
    tags = response.get('Tags', [])
```
- **describe_secret**: Retrieves metadata about the secret, including its tags.
- Tags are extracted and parsed for specific keys:
  - **KeyName**: Name of the API key.
  - **UsagePlan**: Usage plan for attaching the API key.
  - **Project** and **CostCategory**: Custom tags for additional metadata.

---

### 8. `create_secret` Function
```python
if 'RotationEnabled' in metadata and not metadata['RotationEnabled']:
    raise ValueError(f"Secret {secret_arn} is not enabled for rotation")
```
- Checks if **rotation** is enabled for the secret.
- If disabled, it raises an error.

#### Check for Existing Secret Versions
```python
versions = metadata['VersionIdsToStages']
if token in versions and 'AWSCURRENT' in versions[token]:
    logger.info(f"Token {token} is already set as AWSCURRENT for secret {secret_arn}")
    return
```
- Avoids recreating secrets if the token is already marked as `AWSCURRENT`.

#### Create a New API Key
```python
new_api_key = apigateway_client.create_api_key(
    name=key_name,
    description="API key created during rotation",
    enabled=True,
    tags={tag['Key']: tag['Value'] for tag in tags}
)
```
- Creates a **new API key** in API Gateway with the name and tags retrieved earlier.

#### Attach Usage Plan
```python
if usage_plan:
    apigateway_client.create_usage_plan_key(
        usagePlanId=usage_plan,
        keyId=new_api_key['id'],
        keyType='API_KEY'
    )
```
- Attaches the API key to the specified **usage plan**.

#### Store API Key in Secrets Manager
```python
secrets_manager_client.put_secret_value(
    SecretId=secret_arn,
    ClientRequestToken=token,
    SecretString=json.dumps(secret_value),
    VersionStages=['AWSPENDING']
)
```
- Stores the new API key in Secrets Manager with the `AWSPENDING` version.

---

### 9. `set_secret` Function
```python
def set_secret(secret_arn, token):
    pass
```
- Placeholder function as no explicit actions are required in this step.

---

### 10. `test_secret` Function
```python
secret_value = secrets_manager_client.get_secret_value(
    SecretId=secret_arn,
    VersionId=token,
    VersionStage='AWSPENDING'
)
```
- Retrieves the pending version of the secret.

#### Validate API Key
```python
response = apigateway_client.get_api_key(apiKey=api_key, includeValue=True)
if not response['enabled']:
    raise Exception("API key is not enabled")
```
- Ensures the API key exists and is **enabled** in API Gateway.

---

### 11. `finish_secret` Function
#### Move to `AWSCURRENT`
```python
secrets_manager_client.update_secret_version_stage(
    SecretId=secret_arn,
    VersionStage='AWSCURRENT',
    MoveToVersionId=token,
    RemoveFromVersionId=current_version
)
```
- Promotes the pending version to **AWSCURRENT** and demotes the old version.

#### Delete Old API Key
```python
apigateway_client.delete_api_key(apiKey=old_api_key)
```
- Deletes the old API key to ensure cleanup after rotation.

---

## Execution Flow
1. **createSecret**: Create a new API key, attach it to a usage plan, and store it in Secrets Manager.
2. **setSecret**: Placeholder (no explicit actions required).
3. **testSecret**: Validate the new API key.
4. **finishSecret**: Promote the new API key to `AWSCURRENT` and delete the old key.

---

## Prerequisites
- **IAM Role Permissions**:
  - `secretsmanager:*`
  - `apigateway:*`
- **Secrets Manager**: Rotation must be enabled for the secret.
- **Tags**: `KeyName`, `UsagePlan`, `Project`, and `CostCategory` for API key management.

---

## Logging and Debugging
- Logs key steps for debugging using `INFO` and `ERROR` levels.
- Common errors include missing permissions, API key not found, or rotation not enabled.

---

## Conclusion
This Lambda function enables automated rotation of API keys in AWS using Secrets Manager and API Gateway, ensuring secure and managed key rotation lifecycle.

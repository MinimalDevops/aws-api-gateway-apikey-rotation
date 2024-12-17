import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets_manager_client = boto3.client('secretsmanager')
apigateway_client = boto3.client('apigateway')

def lambda_handler(event, context):
    step = event['Step']
    token = event['ClientRequestToken']
    secret_arn = event['SecretId']

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
    except Exception as e:
        logger.error(f"Error in step {step} for token {token} and secret {secret_arn}: {e}")
        raise

def get_tags_from_secret(secret_arn):
    response = secrets_manager_client.describe_secret(SecretId=secret_arn)
    tags = response.get('Tags', [])
    key_name = "RotatedAPIKey"
    usage_plan = None
    project_tag = None
    cost_category_tag = None

    for tag in tags:
        if tag['Key'] == 'KeyName':
            key_name = tag['Value']
        elif tag['Key'] == 'UsagePlan':
            usage_plan = tag['Value']
        elif tag['Key'] == 'Project':
            project_tag = tag
        elif tag['Key'] == 'CostCategory':
            cost_category_tag = tag
    
    return key_name, usage_plan, project_tag, cost_category_tag

def create_secret(secret_arn, token):
    metadata = secrets_manager_client.describe_secret(SecretId=secret_arn)
    if 'RotationEnabled' in metadata and not metadata['RotationEnabled']:
        raise ValueError(f"Secret {secret_arn} is not enabled for rotation")

    versions = metadata['VersionIdsToStages']
    if token in versions and 'AWSCURRENT' in versions[token]:
        logger.info(f"Token {token} is already set as AWSCURRENT for secret {secret_arn}")
        return

    try:
        secret_value = secrets_manager_client.get_secret_value(
            SecretId=secret_arn,
            VersionId=token,
            VersionStage='AWSPENDING'
        )
        secret_dict = json.loads(secret_value['SecretString'])
        logger.info(f"Found existing pending secret value for token {token}")
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        key_name, usage_plan, project_tag, cost_category_tag = get_tags_from_secret(secret_arn)
        
        tags = []
        if project_tag:
            tags.append(project_tag)
        if cost_category_tag:
            tags.append(cost_category_tag)
        
        new_api_key = apigateway_client.create_api_key(
            name=key_name,
            description="API key created during rotation",
            enabled=True,
            tags={tag['Key']: tag['Value'] for tag in tags}
        )

        if usage_plan:
            apigateway_client.create_usage_plan_key(
                usagePlanId=usage_plan,
                keyId=new_api_key['id'],
                keyType='API_KEY'
            )
            logger.info(f"Attached API key {new_api_key['id']} to usage plan {usage_plan}")

        secret_value = {
            'apiKey': new_api_key['id'],
            'apiKeyValue': new_api_key['value']
        }

        secrets_manager_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret_value),
            VersionStages=['AWSPENDING']
        )
        logger.info(f"Created new API key {new_api_key['id']} with name {key_name} and stored it as AWSPENDING version")

def set_secret(secret_arn, token):
    # Typically, no action needed here as the new secret value is already set in create_secret
    pass

def test_secret(secret_arn, token):
    try:
        secret_value = secrets_manager_client.get_secret_value(
            SecretId=secret_arn,
            VersionId=token,
            VersionStage='AWSPENDING'
        )
        secret_dict = json.loads(secret_value['SecretString'])
        api_key = secret_dict['apiKey']

        response = apigateway_client.get_api_key(apiKey=api_key, includeValue=True)
        if not response['enabled']:
            raise Exception("API key is not enabled")
        logger.info(f"Tested API key {api_key} successfully")
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        logger.error(f"ResourceNotFoundException: AWSPENDING version not found for token {token}")
        raise
    except Exception as e:
        logger.error(f"Failed to test secret: {e}")
        raise

def finish_secret(secret_arn, token):
    metadata = secrets_manager_client.describe_secret(SecretId=secret_arn)
    current_version = None

    for version in metadata['VersionIdsToStages']:
        if 'AWSCURRENT' in metadata['VersionIdsToStages'][version]:
            current_version = version
            break

    try:
        secrets_manager_client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage='AWSCURRENT',
            MoveToVersionId=token,
            RemoveFromVersionId=current_version
        )
        logger.info(f"Moved version {token} to AWSCURRENT for secret {secret_arn}")

        # Retrieve the old API key information
        old_secret_value = secrets_manager_client.get_secret_value(
            SecretId=secret_arn,
            VersionId=current_version,
            VersionStage='AWSPREVIOUS'
        )
        old_api_key = json.loads(old_secret_value['SecretString'])['apiKey']

        # Delete the old API key
        try:
            apigateway_client.delete_api_key(apiKey=old_api_key)
            logger.info(f"Deleted old API key {old_api_key}")
        except apigateway_client.exceptions.NotFoundException:
            logger.warning(f"Old API key {old_api_key} not found, might already be deleted")
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        logger.error(f"ResourceNotFoundException: Current version not found for token {current_version}")
        raise
    except Exception as e:
        logger.error(f"Failed to finish secret rotation: {e}")
        raise
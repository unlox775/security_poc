# unset the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
export AWS_PROFILE=codeorg-dev
export AWS_REGION=us-west-2

function cleanup_iam_user() {
    local IAM_USER="$1"

    if [[ -z "$IAM_USER" ]]; then
        echo "Please provide an IAM username as an argument."
        return 1
    fi

    # Delete access keys
    for key in $(aws iam list-access-keys --user-name "$IAM_USER" --query 'AccessKeyMetadata[*].AccessKeyId' --output text); do
        echo "Deleting access key $key for user $IAM_USER..."
        aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$key"
    done

    # Detach managed policies
    for policy_arn in $(aws iam list-attached-user-policies --user-name "$IAM_USER" --query 'AttachedPolicies[*].PolicyArn' --output text); do
        echo "Detaching policy $policy_arn from user $IAM_USER..."
        aws iam detach-user-policy --user-name "$IAM_USER" --policy-arn "$policy_arn"
    done

    # Delete inline policies
    for policy_name in $(aws iam list-user-policies --user-name "$IAM_USER" --query 'PolicyNames' --output text); do
        echo "Deleting inline policy $policy_name from user $IAM_USER..."
        aws iam delete-user-policy --user-name "$IAM_USER" --policy-name "$policy_name"
    done

    # Delete the user
    echo "Deleting user $IAM_USER..."
    aws iam delete-user --user-name "$IAM_USER"
}

function cleanup_iam_role() {
    local ROLE_NAME="$1"

    if [[ -z "$ROLE_NAME" ]]; then
        echo "Please provide an IAM role name as an argument."
        return 1
    fi

    # Detach managed policies
    for policy_arn in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query 'AttachedPolicies[*].PolicyArn' --output text); do
        echo "Detaching policy $policy_arn from role $ROLE_NAME..."
        aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$policy_arn"
    done

    # Delete inline policies
    for policy_name in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output text); do
        echo "Deleting inline policy $policy_name from role $ROLE_NAME..."
        aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$policy_name"
    done

    # Delete the role
    echo "Deleting role $ROLE_NAME..."
    aws iam delete-role --role-name "$ROLE_NAME"
}

# remove the LimitedUser and LimitedUserPolicy
cleanup_iam_user LimitedUser

# remove the OPSuperUserRole role, and policy OPSuperUserAccess
cleanup_iam_role OPSuperUserRole

# remove the SecurityPOC Cloudformation stack
echo "Deleting SecurityPOC Cloudformation stack..."
aws cloudformation delete-stack --stack-name SecurityPOC

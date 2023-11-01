# unset the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
export AWS_PROFILE=codeorg-dev
export AWS_REGION=us-west-2
export ACCOUNT_ID=165336972514

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

function cleanup_stack_set_instances() {
    local STACK_SET_NAME="$1"

    if [[ -z "$STACK_SET_NAME" ]]; then
        echo "Please provide a StackSet name as an argument."
        return 1
    fi

    # List all StackSet instances
    for instance in $(aws cloudformation list-stack-instances --stack-set-name "$STACK_SET_NAME" --query 'Summaries[*].StackId' --output text); do
        # Get Stack Name and Account ID from StackId
        local STACK_NAME=$(echo $instance | cut -d':' -f6 | cut -d'/' -f2)
        local ACCOUNT_ID=$(echo $instance | cut -d':' -f5)

        echo "Deleting StackSet instance with Stack Name: $STACK_NAME in Account: $ACCOUNT_ID..."
        
        # Delete the stack instance from the stack set.
        # If you want to retain stacks, remove --retain-stacks flag
        aws cloudformation delete-stack-instances --stack-set-name "$STACK_SET_NAME" --accounts "$ACCOUNT_ID" --regions "$AWS_REGION" --retain-stacks

        # It's a good idea to have some error handling, in case a stack instance deletion fails. 
        # Wait for the instance to be deleted
        aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME"
    done

    echo "All instances of StackSet $STACK_SET_NAME have been deleted."
}


# remove the LimitedUser and LimitedUserPolicy
cleanup_iam_user LimitedUser

# remove the OPSuperUserRole role, and policy OPSuperUserAccess
cleanup_iam_role OPSuperUserRole

# remove the SecurityPOC Cloudformation stack
echo "Deleting SecurityPOC Cloudformation stack..."
aws cloudformation delete-stack --stack-name SecurityPOC

# remove the SecurityPOCStackSet Cloudformation stackset
echo "Deleting SecurityPOCStackSet Cloudformation stackset..."
cleanup_stack_set_instances SecurityPOCStackSet
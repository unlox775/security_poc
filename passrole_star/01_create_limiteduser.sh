# unset the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
export AWS_PROFILE=codeorg-dev
export AWS_REGION=us-west-2

aws iam create-user --user-name LimitedUser | cat -
aws iam put-user-policy --user-name LimitedUser --policy-name LimitedUserPolicy --policy-document file://01_limiteduser-policy.json

# Capture the output from the create-access-key command
OUTPUT=$(aws iam create-access-key --user-name LimitedUser)

# Extract the access key and secret key using jq
ACCESS_KEY=$(echo $OUTPUT | jq -r .AccessKey.AccessKeyId)
SECRET_KEY=$(echo $OUTPUT | jq -r .AccessKey.SecretAccessKey)

# Export the variables
export AWS_ACCESS_KEY_ID=$ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$SECRET_KEY
export AWS_DEFAULT_REGION=us-west-1  # Or your desired region

echo "Credentials set for LimitedUser."


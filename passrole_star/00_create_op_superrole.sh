# unset the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
export AWS_PROFILE=codeorg-dev
export AWS_REGION=us-west-2

aws iam create-role --role-name OPSuperUserRole --assume-role-policy-document file://00_trust-policy.json | cat -
aws iam put-role-policy --role-name OPSuperUserRole --policy-name OPSuperUserAccess --policy-document file://00_op_superrole-policy.json

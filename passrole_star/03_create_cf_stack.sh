# Output first 4 chars of both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:4}..."
echo "AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:4}..."

# Stop here if both of those variables are not set
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
  echo "AWS_ACCESS_KEY_ID and/or AWS_SECRET_ACCESS_KEY not set."
  exit 1
fi

# Create a cloudformation stack
aws cloudformation create-stack-set \
  --stack-set-name SecurityPOCStackSet \
  --template-body file://03_cf_template.yml \
  --administration-role-arn arn:aws:iam::165336972514:role/OPSuperUserRole \
  --capabilities CAPABILITY_NAMED_IAM | cat -

aws cloudformation create-stack-instances \
  --stack-set-name SecurityPOCStackSet \
  --accounts 165336972514 \
  --regions us-west-2 \
  --operation-role-name OPSuperUserRole \
  --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1 | cat -


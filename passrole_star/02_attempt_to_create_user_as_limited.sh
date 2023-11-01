# Output first 4 chars of both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:4}..."
echo "AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:0:4}..."

# Stop here if both of those variables are not set
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
  echo "AWS_ACCESS_KEY_ID and/or AWS_SECRET_ACCESS_KEY not set."
  exit 1
fi

# Create a new user
aws iam create-user --user-name SuperUser | cat -
aws iam put-user-policy --user-name SuperUser --policy-name SuperUserPolicy --policy-document file://02_superuser-policy.json

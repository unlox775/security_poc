echo "Resetting... (Deleting old leftovers from last run)"
echo "-------------------------"
. 99_cleanup.sh

echo "Creating SuperUser role..."
echo "-------------------------"
. 00_create_op_superrole.sh

echo "Creating LimitedUser..."
echo "-------------------------"
. 01_create_limiteduser.sh

echo "Sleeping for 15 seconds to allow IAM to propagate..."
sleep 15

echo "Attempting to Create a User as Limited [Expected to FAIL]..."
echo "-------------------------"
. 02_attempt_to_create_user_as_limited.sh

echo "Creating CloudFormation stack..."
echo "-------------------------"
. 03_create_cf_stack.sh

echo sleeping 5 mins before cleaning up, Ctrl-C to cancel
sleep 300

echo "Resetting... (Deleting old leftovers from last run)"
echo "-------------------------"
. 99_cleanup.sh

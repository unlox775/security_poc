# passrole_star Proof of Concept

This proof of concept illustrates the inherent dangers associated with granting overly permissive `PassRole` permissions, especially when using a wildcard (`*`). At the heart of this demonstration is the fact that even limited users can escalate their privileges if granted the ability to assume any role in the system via `PassRole *`.

## Overview

The PoC focuses on two primary scenarios:
1. **Basic `PassRole *`**: Shows how a low-privileged user with solely `PassRole *` permission can assume any role, provided the target role has a trust entity for the desired service. This can result in a low-privileged user executing actions of a super user or any other role.
   
2. **Block List Weakness**: Building on the basic scenario, this test showcases a common but risky practice where specific actions are denied in IAM policies. On the surface, it seems like only a specific high-privilege role can execute a subset of CloudFormation actions. However, because of the nature of block list configurations, other actions (like creating a stack set) are inadvertently allowed, demonstrating the pitfalls of using deny rules with specific exemptions.

## Usage

1. Run the main script using:
   ```
   . ./__run__all.sh
   ```

2. Ensure to cleanup created resources and revert configurations after completing the PoC. Run:
   ```
   . ./99_cleanup.sh
   ```

## Key Takeaways

- Using `PassRole *` can lead to unintentional and potentially dangerous privilege escalations.
- Relying on deny rules and block lists can be misleading. Without comprehensive coverage, it leaves room for overlooked permissions and potential vulnerabilities.
- Always adhere to the principle of least privilege, granting only the permissions necessary and avoiding wildcards where possible.

## Important Notes

- This PoC sets up several roles with varying privilege levels for demonstration. It's imperative to run the cleanup script after testing to avoid lingering security risks.
- Use this PoC in a controlled and safe environment. Ensure not to use this in production or sensitive environments.


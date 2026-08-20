from firewall.engine import Firewall


fw = Firewall()


def ask_for_approval(tool, arguments):
    print("\n HUMAN APPROVAL REQUIRED")
    print(f"Tool: {tool}")
    print(f"Arguments: {arguments}")

    answer = input("Allow this action? [y/N]: ").strip().lower()

    return answer == "y"


def protected_call(agent, tool, arguments, real_tool):
    decision = fw.check(agent, tool, arguments)

    print(
        f"\n[FIREWALL] {tool} -> "
        f"{decision.action.upper()}"
    )

    # Automatic block
    if decision.action == "deny":
        return {
            "error": "Blocked by firewall",
            "reason": decision.reason
        }

    # Human approval
    if decision.action == "approval":
        approved = ask_for_approval(tool, arguments)

        if not approved:
            return {
                "error": "Rejected by human",
                "reason": "Human denied the action"
            }

    # Allowed or approved
    return real_tool(**arguments)


def read_file(path):
    return f"READING: {path}"


def delete_file(path):
    return f"DELETING: {path}"


def send_payment(amount):
    return f"SENDING PAYMENT: ${amount}"


if __name__ == "__main__":

    print(
        protected_call(
            "test-agent",
            "github.read_file",
            {"path": "README.md"},
            read_file
        )
    )

    print(
        protected_call(
            "test-agent",
            "github.delete_file",
            {"path": "production.env"},
            delete_file
        )
    )

    print(
        protected_call(
            "finance-agent",
            "payments.send",
            {"amount": 20},
            send_payment
        )
    )

    print(
        protected_call(
            "finance-agent",
            "payments.send",
            {"amount": 500},
            send_payment
        )
    )

    print(
        protected_call(
            "finance-agent",
            "payments.send",
            {"amount": 2000},
            send_payment
        )
    )
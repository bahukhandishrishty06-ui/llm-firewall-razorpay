"""Terminal ANSI Color & Layout Formatters for PayGuard CLI."""

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

def format_banner() -> str:
    return f"""
{BOLD}{MAGENTA}======================================================================{RESET}
{BOLD}{WHITE}   PAYGUARD — Real-Time LLM Firewall for Payment Agents{RESET}
{DIM}   Defense-in-depth protection for agentic commerce & Razorpay APIs{RESET}
{BOLD}{MAGENTA}======================================================================{RESET}
"""

def format_verdict(verdict: str, confidence: float, layer: str, reason: str) -> str:
    color = GREEN if verdict == "allow" else (RED if verdict == "block" else YELLOW)
    status = "APPROVED" if verdict == "allow" else ("BLOCKED" if verdict == "block" else "FLAGGED")
    return f"""
{BOLD}Decision:{RESET} {color}{BOLD}[{status}]{RESET}
{BOLD}Risk Confidence:{RESET} {confidence:.2%}
{BOLD}Screening Tier:{RESET}  {layer}
{BOLD}Reason:{RESET}          {reason}
"""

def format_tool_call(tool_name: str, args: dict, is_blocked: bool = False) -> str:
    status_str = f"{RED}[BLOCKED]{RESET}" if is_blocked else f"{GREEN}[EXECUTED]{RESET}"
    return f"  {status_str} {BOLD}{tool_name}{RESET}({args})"

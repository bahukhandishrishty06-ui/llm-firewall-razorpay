"""
PayGuard Firewall Orchestrator
Wires Layer 1 (Input Screener) and Layer 2 (Action Screener) together
into a single pipeline that protects the target payment agent.

Flow:
  User Message → [Layer 1: Input Screener] → if BLOCK → return blocked response
                                             → if ALLOW/FLAG → pass to Agent
  Agent Response → if tool call → [Layer 2: Action Screener] → if BLOCK → return blocked
                                                               → if ALLOW → execute tool
                → if text only → return response
"""

import os
import sys
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from firewall.input_screener import screen_input, ScreeningResult
from firewall.action_screener import screen_action, ActionScreeningResult, reset_session
from agent.target_agent import TargetAgent
from agent.tools import execute_tool
from database import log_firewall_decision


REFUND_REQUEST_PATTERN = re.compile(r"\b(refund|return)\b", re.IGNORECASE)


def requires_refund_verification(user_message: str) -> bool:
    """Keep refund requests out of the agent until trusted proof is available."""
    return bool(REFUND_REQUEST_PATTERN.search(user_message))


@dataclass
class FirewallResult:
    """Complete result from the firewall pipeline."""
    verdict: str  # "allow", "block", "flag_for_human"
    confidence: float
    reason: str
    layer: str  # "input_screener", "action_screener", "none"
    agent_response: str = ""
    tool_calls_made: list = field(default_factory=list)
    tool_calls_blocked: list = field(default_factory=list)
    input_screening: dict = None
    action_screenings: list = field(default_factory=list)
    session_id: str = ""
    timestamp: str = ""

    def to_dict(self):
        return asdict(self)


class PayGuardFirewall:
    """
    The main firewall that sits in front of the payment agent.
    Orchestrates input screening → agent processing → action screening.
    """

    def __init__(self, api_key: str = None, block_threshold: float = 0.7,
                 flag_threshold: float = 0.4, use_llm: bool = True,
                 authenticated_customer_id: str = None):
        self.agent = TargetAgent(api_key=api_key)
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.use_llm = use_llm
        self.authenticated_customer_id = authenticated_customer_id
        self.session_id = str(uuid.uuid4())[:8]

    def new_session(self):
        """Start a new session (resets agent conversation and anomaly tracking)."""
        self.agent.reset()
        reset_session(self.session_id)
        self.session_id = str(uuid.uuid4())[:8]

    def process_message(self, user_message: str, skip_input_screening: bool = False) -> FirewallResult:
        """
        Process a user message through the full firewall pipeline.

        1. Screen the input (Layer 1)
        2. If allowed, pass to agent
        3. If agent wants to make tool calls, screen each one (Layer 2)
        4. Execute approved tool calls, block rejected ones
        5. Return final result

        Args:
            user_message: The user's message
            skip_input_screening: Skip Layer 1 (for testing Layer 2 in isolation)

        Returns:
            FirewallResult with complete verdict and details
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # ─── Layer 1: Input Screening ──────────────────────────────────
        input_result = None
        if not skip_input_screening:
            input_result = screen_input(
                text=user_message,
                input_type="direct_input",
                session_id=self.session_id,
                force_llm=self.use_llm,
                block_threshold=self.block_threshold,
                flag_threshold=self.flag_threshold,
                use_llm=self.use_llm,
            )

            if input_result.verdict == "block":
                return FirewallResult(
                    verdict="block",
                    confidence=input_result.confidence,
                    reason=f"[Layer 1 - Input Blocked] {input_result.reason}",
                    layer="input_screener",
                    agent_response="🛡️ PayGuard blocked this message. Reason: " + input_result.reason,
                    input_screening=input_result.to_dict(),
                    session_id=self.session_id,
                    timestamp=timestamp,
                )

        # A free-form chat message cannot supply trustworthy evidence or identity.
        # Stop here and give the customer the next safe step instead of asking the
        # LLM to infer complaint validity or propose a refund tool call.
        if requires_refund_verification(user_message):
            return FirewallResult(
                verdict="flag_for_human",
                confidence=0.75,
                reason="Refund verification required before any refund can be assessed or executed",
                layer="refund_verification",
                agent_response=(
                    "To review a refund request, please submit your order confirmation, "
                    "clear photos of the damage, and a short description of the issue. "
                    "A support reviewer must verify the evidence and your account before "
                    "any refund can be considered."
                ),
                input_screening=input_result.to_dict() if input_result else None,
                session_id=self.session_id,
                timestamp=timestamp,
            )

        # ─── Pass to Agent (get proposed actions) ──────────────────────
        try:
            agent_result = self.agent.process_message_with_proposed_actions(
                user_message, session_id=self.session_id
            )
        except Exception as e:
            return FirewallResult(
                verdict="allow",
                confidence=0.0,
                reason=f"Agent error: {str(e)}",
                layer="none",
                agent_response=f"Sorry, I encountered an error: {str(e)}",
                input_screening=input_result.to_dict() if input_result else None,
                session_id=self.session_id,
                timestamp=timestamp,
            )

        # ─── No Tool Calls → return agent's text response ─────────────
        if not agent_result.get("needs_tool_execution"):
            verdict = "allow"
            if input_result and input_result.verdict == "flag_for_human":
                verdict = "flag_for_human"

            return FirewallResult(
                verdict=verdict,
                confidence=input_result.confidence if input_result else 0.0,
                reason=input_result.reason if input_result else "No threats detected",
                layer="input_screener" if input_result else "none",
                agent_response=agent_result.get("response", ""),
                input_screening=input_result.to_dict() if input_result else None,
                session_id=self.session_id,
                timestamp=timestamp,
            )

        # ─── Layer 2: Action Screening ─────────────────────────────────
        tool_calls_made = []
        tool_calls_blocked = []
        action_screenings = []
        tool_results = []
        overall_verdict = "allow"
        max_confidence = input_result.confidence if input_result else 0.0
        reasons = []

        if input_result and input_result.verdict == "flag_for_human":
            reasons.append(f"[Layer 1 - Flagged] {input_result.reason}")

        for proposed_call in agent_result.get("proposed_tool_calls", []):
            tool_name = proposed_call["tool_name"]
            tool_args = proposed_call["tool_args"]
            tool_id = proposed_call["tool_id"]

            # Screen the proposed action
            action_result = screen_action(
                tool_name=tool_name,
                tool_args=tool_args,
                conversation_history=self.agent.conversation_history,
                session_id=self.session_id,
                use_llm=self.use_llm,
                block_threshold=self.block_threshold,
                flag_threshold=self.flag_threshold,
                authenticated_customer_id=self.authenticated_customer_id,
            )
            screening = action_result.to_dict()
            # Preserve the proposed action alongside its policy decision so the
            # UI can replay the complete decision path without guessing.
            screening.update({"tool_name": tool_name, "tool_args": tool_args})
            action_screenings.append(screening)

            if action_result.verdict == "block":
                # Block this tool call
                tool_calls_blocked.append({
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "reason": action_result.reason,
                    "confidence": action_result.confidence,
                })
                overall_verdict = "block"
                max_confidence = max(max_confidence, action_result.confidence)
                reasons.append(f"[Layer 2 - Action Blocked] {tool_name}: {action_result.reason}")

                # Send a blocked result back to the agent
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps({
                        "success": False,
                        "error": f"Action blocked by PayGuard firewall: {action_result.reason}",
                        "blocked": True,
                    }),
                    "is_error": True,
                })

            elif action_result.verdict == "flag_for_human":
                # Flag but still execute (with warning)
                result = execute_tool(tool_name, tool_args, session_id=self.session_id)
                tool_calls_made.append({
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "result": result,
                    "flagged": True,
                    "flag_reason": action_result.reason,
                })
                if overall_verdict != "block":
                    overall_verdict = "flag_for_human"
                max_confidence = max(max_confidence, action_result.confidence)
                reasons.append(f"[Layer 2 - Flagged] {tool_name}: {action_result.reason}")

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(result),
                })

            else:
                # Allow — execute the tool
                result = execute_tool(tool_name, tool_args, session_id=self.session_id)
                tool_calls_made.append({
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "result": result,
                })

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(result),
                })

        # ─── Continue agent conversation with tool results ─────────────
        try:
            continuation = self.agent.continue_with_tool_results(
                tool_results, session_id=self.session_id
            )
            agent_response = continuation.get("response", "")
        except Exception as e:
            agent_response = f"Error continuing conversation: {str(e)}"

        # If actions were blocked, prepend a warning to the response
        if tool_calls_blocked:
            block_summary = "; ".join(
                f"{tc['tool_name']}({json.dumps(tc['tool_args'])})" 
                for tc in tool_calls_blocked
            )
            agent_response = (
                f"🛡️ PayGuard blocked {len(tool_calls_blocked)} action(s): {block_summary}\n\n"
                + agent_response
            )

        final_reason = " | ".join(reasons) if reasons else "All checks passed"

        return FirewallResult(
            verdict=overall_verdict,
            confidence=round(max_confidence, 4),
            reason=final_reason,
            layer="action_screener" if action_screenings else ("input_screener" if input_result else "none"),
            agent_response=agent_response,
            tool_calls_made=tool_calls_made,
            tool_calls_blocked=tool_calls_blocked,
            input_screening=input_result.to_dict() if input_result else None,
            action_screenings=action_screenings,
            session_id=self.session_id,
            timestamp=timestamp,
        )


class UnprotectedAgent:
    """
    Wrapper for running the agent WITHOUT the firewall.
    Used for before/after comparison in the dashboard.
    """

    def __init__(self, api_key: str = None):
        self.agent = TargetAgent(api_key=api_key)

    def reset(self):
        self.agent.reset()

    def process_message(self, user_message: str) -> dict:
        """Process message with no firewall protection."""
        try:
            result = self.agent.process_message(user_message, session_id="unprotected")
            return {
                "response": result.get("response", ""),
                "tool_calls": result.get("tool_calls", []),
                "protected": False,
            }
        except Exception as e:
            return {
                "response": f"Error: {str(e)}",
                "tool_calls": [],
                "protected": False,
            }


# ─── Heuristic-Only Mode (no LLM, for fast evaluation) ────────────────────────

def screen_input_heuristic_only(text: str, block_threshold: float = 0.7,
                                 flag_threshold: float = 0.4) -> ScreeningResult:
    """Screen input using only heuristics (no LLM call). Fast and free."""
    return screen_input(
        text=text,
        input_type="direct_input",
        force_llm=False,
        block_threshold=block_threshold,
        flag_threshold=flag_threshold,
        use_llm=False,
    )


# ─── CLI Testing ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from agent.tools import seed_test_orders
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

    print("Seeding test data...")
    seed_test_orders()

    print("\n" + "=" * 60)
    print("PayGuard Firewall — Interactive Mode")
    print("=" * 60)
    print("Type 'quit' to exit, 'reset' to start new session")
    print("Type 'nollm' to toggle LLM screening on/off\n")

    use_llm = True
    firewall = PayGuardFirewall(use_llm=use_llm)

    while True:
        user_input = input("Customer: ").strip()
        if user_input.lower() == "quit":
            break
        if user_input.lower() == "reset":
            firewall.new_session()
            print("Session reset.\n")
            continue
        if user_input.lower() == "nollm":
            use_llm = not use_llm
            firewall.use_llm = use_llm
            print(f"LLM screening: {'ON' if use_llm else 'OFF'}\n")
            continue

        result = firewall.process_message(user_input)

        # Display verdict
        verdict_emoji = {"allow": "✅", "block": "🚫", "flag_for_human": "⚠️"}
        print(f"\n{verdict_emoji.get(result.verdict, '❓')} Verdict: {result.verdict} "
              f"(confidence: {result.confidence:.2f})")
        print(f"Layer: {result.layer}")
        print(f"Reason: {result.reason}")

        if result.tool_calls_blocked:
            print(f"\n🛡️ Blocked actions:")
            for tc in result.tool_calls_blocked:
                print(f"  ✗ {tc['tool_name']}({json.dumps(tc['tool_args'])}) — {tc['reason']}")

        if result.tool_calls_made:
            print(f"\n✅ Executed actions:")
            for tc in result.tool_calls_made:
                print(f"  ✓ {tc['tool_name']}({json.dumps(tc['tool_args'])})")

        print(f"\nAgent: {result.agent_response}\n")

import argparse
import json

from .evaluate import evaluate, to_markdown
from .monitor import Action, EnsembleMonitor, LLMMonitor, RuleMonitor

ap = argparse.ArgumentParser(prog="action_monitor", description="Trusted monitoring for AI agent actions.")
sub = ap.add_subparsers(dest="cmd", required=True)
ev = sub.add_parser("eval", help="Evaluate a monitor on the labeled transcripts")
ev.add_argument("--monitor", default="rules", choices=["rules", "llm", "ensemble"])
sc = sub.add_parser("score", help="Score one action")
sc.add_argument("command")
sc.add_argument("--task", default="")
sc.add_argument("--monitor", default="rules", choices=["rules", "llm", "ensemble"])
args = ap.parse_args()

def make(name):
    if name == "rules":
        return RuleMonitor()
    if name == "llm":
        return LLMMonitor()
    return EnsembleMonitor(RuleMonitor(), LLMMonitor())

m = make(args.monitor)
if args.cmd == "eval":
    print(to_markdown(evaluate(m)))
else:
    s = m.score(Action("bash", args.command, args.task))
    print(json.dumps({"suspicion": s.suspicion, "reasons": s.reasons}, indent=2))

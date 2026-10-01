"""Run the reference prompt battery against a local Ollama model.

Usage:
    python3 run_ollama_reference.py prompts.jsonl outputs.jsonl \
        --model qwen2.5:0.5b --samples 3

Reads one prompt per line ({"id", "check", "messages"}), sends each to the
local Ollama server SAMPLES times with the decoding settings below, and writes
one output per line ({"id", "sample", "response", "prompt_eval_count",
"eval_count", "done_reason"}), in prompt order then sample order. That order is
what `tvc commit-items` commits to, so a re-run must keep it.

Standard library only, so anyone can run it next to `ollama serve`.
"""
import argparse
import json
import urllib.request

# The decoding settings the published reference-setup record states. Change
# one and you are running a different reference.
OPTIONS = {"temperature": 0, "seed": 42, "num_predict": 128}


def chat(model: str, messages: list) -> dict:
    body = json.dumps(
        {"model": model, "messages": messages, "stream": False, "options": OPTIONS}
    ).encode()
    request = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("prompts")
    parser.add_argument("outputs")
    parser.add_argument("--model", required=True)
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()

    with open(args.prompts) as handle:
        prompts = [json.loads(line) for line in handle if line.strip()]

    with open(args.outputs, "w") as out:
        for prompt in prompts:
            for sample in range(args.samples):
                reply = chat(args.model, prompt["messages"])
                record = {
                    "id": prompt["id"],
                    "sample": sample,
                    "response": reply["message"]["content"],
                    "prompt_eval_count": reply.get("prompt_eval_count"),
                    "eval_count": reply.get("eval_count"),
                    "done_reason": reply.get("done_reason"),
                }
                out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                print(f"{prompt['id']:>3} sample {sample}: {record['response'][:60]!r}")


if __name__ == "__main__":
    main()

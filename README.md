# FirmAgent

![FirmAgent framework](Pre_Fuzzing/image.png)

FirmAgent is a research toolkit for collecting runtime taint/coverage data from authorized, re-hosted IoT web services. It combines IDA-based pre-fuzzing, QEMU instrumentation, API fuzzing, and optional LLM-assisted taint analysis.

Only use it on firmware and services that you own or are explicitly authorized to test.

## Requirements

- Python 3.8+
- IDA Pro with `idat`/`idat64` for pre-fuzzing
- Docker and a prepared Greenhouse/re-hosting image for runtime tests
- An instrumented QEMU binary and a shared host directory for its trace log
- An LLM endpoint only when using API extraction or `LLMATaint.py`

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Set tools and LLM configuration through the environment. Do not commit keys:

```bash
export IDAT_BIN=/path/to/idat64
export Private_API_KEY=...
export LLM_BASE_URL=https://your-endpoint
export LLM_MODEL=your-model
```

## Reproduction workflow

### 1. Pre-fuzzing

Run IDA decompilation, sink-scope extraction, and CFG distance calculation:

```bash
Pre_Fuzzing/run.sh /path/to/httpd
```

The command writes artifacts next to the target binary:

```text
export-for-ai-httpd/       IDA decompilation evidence
sink_scope_addr.txt        QEMU address filter ranges
sink_cfg.json              real CFG, roots, edges, and sink blocks
sink_distance_scores.json  per-block distance/proximity/score
sink_distance_scores.csv   tabular version of the scores
```

API and parameter extraction is an optional LLM step. The command is intentionally commented out in `run.sh`; run it explicitly when needed:

```bash
python3 Pre_Fuzzing/llm_extract_api_params.py \
  --input /path/to/export-for-ai-httpd \
  --output /path/to/Pre_fuzzing.json
```

`Pre_fuzzing.json` must contain at least:

```json
{
  "api_endpoints": ["/apply.cgi"],
  "para": ["action", "mode"]
}
```

It may also contain mutation values:

```json
{
  "dictionary": {
    "global_values": ["0", "1", "enable", "disable"],
    "parameter_values": {
      "action": ["apply", "save"],
      "mode": ["ap", "sta"]
    }
  }
}
```

### 2. Start the re-hosted service

Create a running Greenhouse/re-hosting container with `/scratch` mounted to a host directory. Start the service under instrumented QEMU and restrict tracing to the sink scope:

```bash
FuzzingRecord/rehost_session.sh start \
  --container <container> \
  --dfilter "$(python3 FuzzingRecord/make_dfilter.py /path/to/sink_scope_addr.txt)"
```

The launcher sets:

```text
QEMU_DFILTER        comma-separated sink-scope ranges
QEMU_LOG=exec,nochain
QEMU_LOG_FILENAME=/scratch/qemu_trace.log
```

Use `FuzzingRecord/rehost_session.sh stop --container <container>` after fuzzing. This resets the trace log. Keep the traced service running only during an active session.

### 3. Run the fuzzer

Legacy taint traversal (no distance/coverage feedback):

```bash
python3 FuzzingRecord/Fuzzer.py \
  --json-file /path/to/Pre_fuzzing.json \
  --host <container-ip> \
  --delay 0.5 \
  --tag-mode unique
```

CFG-guided feedback mode (requires both a distance file and QEMU log):

```bash
python3 FuzzingRecord/Fuzzer.py \
  --json-file /path/to/Pre_fuzzing.json \
  --distance-file /path/to/sink_distance_scores.json \
  --qemu-log /host/shared/qemu_trace.log \
  --host <container-ip> \
  --feedback-settle 0.3 \
  --iterations 1000 \
  --random-seed 1 \
  --tag-mode unique
```

In feedback mode the fuzzer combines parameter dictionary mutations with runtime basic-block/edge coverage and shortest distance to a sink. If the trace file is missing, rotated, or truncated, that iteration is marked invalid and the loop continues.

Outputs are written beside `Pre_fuzzing.json`:

```text
result.json              request/response and feedback records
result_stream.ndjson     append-only request stream
fuzzing_summary.json     coverage, distance, corpus, and mutation statistics
```

### 4. Build `Source.json` and analyze taint

For exact request-to-trace attribution, run the sidecar before fuzzing and use unique tags:

```bash
python3 FuzzingRecord/taint_monitor.py \
  --stream /path/to/result_stream.ndjson \
  --qemu-log /host/shared/qemu_trace.log \
  --out /path/to/trace_windows.jsonl \
  --settle 0.3
```

After fuzzing:

```bash
python3 FuzzingRecord/build_source_json.py \
  --qemu-log /host/shared/qemu_trace.log \
  --windows /path/to/trace_windows.jsonl \
  --result-stream /path/to/result_stream.ndjson \
  --output /path/to/Source.json
```

Then run the optional LLM analysis:

```bash
python3 LLMATaint.py \
  -b /path/to/httpd \
  -p True \
  -t command_injection \
  -o /path/to/results
```

Place `Source.json` in the same directory as the target binary. `Indirect_call.json` or `indirect_data.json` may also be supplied when available.


### Example Commands Recap

**Run pre-fuzzing (single command):**

```
./Pre_Fuzzing/run.sh /path/to/httpd
```

This generates `Pre_fuzzing.json`, `sink_scope_addr.txt`, and distance scores in the same directory as the binary.

**Run fuzzing (host):**

⚠️ Remember to customize `FuzzingRecord/Fuzzer.py` request templates first!

```
export QEMU_DFILTER="Sink scope" (docker)
python FuzzingRecord/Fuzzer.py \
  --json-file Pre_fuzzing.json \
  --delay 0.5 \
  --host 192.168.0.1
```

This generates `result.json` (request packets and responses). A separate runtime-monitoring step should generate `Source.json` / `source.json` for taint analysis.

**Run taint-to-PoC agent:**

Place `Source.json` or `source.json` in the same directory as the binary, then:

```
python LLMATaint.py \
  -b ./bin/httpd \
  -p False \
  -t ci \
  -o ./results/ASUS \
  -m R1_official
```



**Reference**

If you use or cite this work, please reference:

```bibtex
@inproceedings{Ji2026FirmAgent,
  author    = {Ji, Jiangan and Zhang, Chao and Gan, Shuitao and Lin, Jian and Liu, Hangtian and Liu, Tieming and Zheng, Lei and Jia, Zhipeng},
  title     = {FirmAgent: Leveraging Fuzzing to Assist LLM Agents with IoT Firmware Vulnerability Discovery},
  booktitle = {Network and Distributed System Security (NDSS) Symposium},
  year      = {2026},
  month     = {February},
  pages     = {1--16},
  address   = {San Diego, CA, USA},
  doi       = {10.14722/ndss.2026.231943},
  isbn      = {979-8-9919276-8-0},
  url       = {https://dx.doi.org/10.14722/ndss.2026.231943},
}
```

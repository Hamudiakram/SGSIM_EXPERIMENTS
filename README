# SGSIM_EXPERIMENTS

This repository contains the experiment artifacts and scripts used for the SGSim-based evaluation described in the thesis.


SGSim can be obtained from:

`https://github.com/filipholik/SmartGridSim`

## Example layout

The repository was used together with SGSim in a structure like this:

```text
/home/sgsim/
└── SmartGridSim/
    ├── ...
    └── SGSIM_EXPERIMENTS/
        ├── figures/
        │   └── combined/
        ├── results/
        │   └── combined/
        ├── rules/
        ├── runs/
        ├── make_figures.py
        └── run_capture.sh
```

## Repository structure

- `figures/combined/`  
  Generated analysis figures in PDF and PNG format.

- `results/combined/`  
  Exported CSV results from the analysis workflow.

- `rules/`  
  Static OpenFlow rule scripts used for the least-privilege defense.  
  Includes:
  - `zt_all_rules.sh`
  - `zt_dpsgw.sh`
  - `zt_dpshv.sh`
  - `zt_dpsmv.sh`
  - `zt_dpsrs.sh`

- `runs/`  
  Per-run experiment artifacts for baseline, defense, and combined attack conditions.

- `make_figures.py`  
  Python analysis script used to process stored runs into figures and CSV summaries.

- `run_capture.sh`  
  Shell script used to automate packet capture and run archiving.

## Run sets in this repository

The repository contains three run types:

- `baseline_001` to `baseline_010`
- `defense_001` to `defense_010`
- `combined_001` to `combined_005`

## Example run contents

Each run is stored as a self-contained folder under `runs/`.

Example:

```text
runs/
└── baseline_001/
    ├── logs/
    │   ├── host_versions.txt
    │   ├── tshark_DPSHV-eth3.log
    │   ├── tshark_DPSRS-eth1.log
    │   ├── tshark_DPSRS-eth2.log
    │   ├── tshark_DPSRS-eth4.log
    │   └── tshark_DPSRS-eth5.log
    ├── ovs/
    │   ├── CONTROLSW_flows_pre.txt
    │   ├── CONTROLSW_flows_post.txt
    │   ├── DPSGW_flows_pre.txt
    │   ├── DPSGW_flows_post.txt
    │   ├── DPSHV_flows_pre.txt
    │   ├── DPSHV_flows_post.txt
    │   ├── DPSMV_flows_pre.txt
    │   ├── DPSMV_flows_post.txt
    │   ├── DPSRS_flows_pre.txt
    │   ├── DPSRS_flows_post.txt
    │   ├── ... port snapshots ...
    │   ├── ovs_state_pre.txt
    │   └── ovs_vsctl_show_post.txt
    ├── pcaps/
    │   ├── baseline_001_DPSHV-eth3.pcapng
    │   ├── baseline_001_DPSRS-eth1.pcapng
    │   ├── baseline_001_DPSRS-eth2.pcapng
    │   ├── baseline_001_DPSRS-eth4.pcapng
    │   └── baseline_001_DPSRS-eth5.pcapng
    ├── manifest.sha256
    └── run_meta.json
```

Each run folder therefore stores:

- packet captures,
- `tshark` logs,
- Open vSwitch snapshots,
- run metadata,
- a checksum manifest.


## Running packet capture

```bash
sudo ./run_capture.sh <condition> <run_number> <duration_seconds>
```

Examples:

```bash
sudo ./run_capture.sh baseline 1 120
sudo ./run_capture.sh defense 1 120
sudo ./run_capture.sh combined 1 120
```

## Applying the defense rules

Apply all rules at once:

```bash
sh /home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_all_rules.sh
```

Or apply them one by one:

```bash
sh /home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_dpsmv.sh
sh /home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_dpshv.sh
sh /home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_dpsrs.sh
sh /home/sgsim/SmartGridSim/SGSIM_EXPERIMENTS/rules/zt_dpsgw.sh
```

## Running the analysis

```bash
python ./make_figures.py \
  --runs_root ./runs \
  --baseline_prefix baseline_ \
  --defense_prefix defense_ \
  --start 1 \
  --end 10 \
  --hmi_iface DPSRS-eth4 \
  --uplink_iface DPSRS-eth2 \
  --attack_prefix combined_ \
  --attack_start 1 \
  --attack_end 5 \
  --attacker_iface DPSRS-eth5 \
  --outdir ./figures/combined \
  --export_envelopes_csv ./results/combined/envelopes_with_paired_deltas.csv
```

## Outputs

The analysis generates:

- figures in `figures/combined/`
- CSV summaries in `results/combined/`

Main generated figures include:

- `fig1_hmi_baseline_vs_defense.pdf`
- `fig1_hmi_baseline_vs_defense.png`
- `fig2_attacker_vs_hmi_multi.pdf`
- `fig2_attacker_vs_hmi_multi.png`
- `fig3_containment_uplink_vs_hmi_multi.pdf`
- `fig3_containment_uplink_vs_hmi_multi.png`

Main exported CSV output:

- `results/combined/envelopes_with_paired_deltas.csv`

## Notes

The stored runs preserve packet captures, logs, OVS snapshots, and metadata for reproducibility.

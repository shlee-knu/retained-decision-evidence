"""Independent release reconciliation for matched diagnostic timing and prospective scores.

This checks saved observations and aggregates, not new host performance, human
utility, or a journal decision. Mathematical adapter tests are run by the suite.
"""
from collections import Counter
from hashlib import sha256
import json
import statistics
import subprocess

from verify_expanded import ROOT, table_rows


def verify(a):
    base = "paper/history/ieee_access_pre_focus_20261008/"
    saved = a.load(base + "manifest.json")
    a.same(saved["tag"], "ieee-access-v05-pre-focus-20261008", "focused baseline tag", "focused-baseline")
    a.same(saved["commit"], "63de3d6e8c084fbfd33eba331820f0542c785acd", "focused baseline commit", "focused-baseline")
    for row in saved["files"]:
        a.pin(base + row["path"], row["sha256"])
    if (ROOT / ".git").exists():
        commit=subprocess.check_output(["git","rev-parse",saved["tag"]+"^{commit}"],cwd=ROOT,text=True).strip()
        a.same(commit,saved["commit"],"focused annotated tag resolves correctly","focused-baseline")
        raw=subprocess.check_output(["git","show",saved["tag"]+":paper/manuscript_ieee_access_applied.md"],cwd=ROOT)
        a.same(sha256(raw).hexdigest(),"31553aeab5d58c026e12fb0ad775991cf43c390485ec470d46d9d4ffed1f4aa9", "focused Git source preserved", "focused-baseline")
    frozen=a.load("results/focused_revision/reviews/baseline_freeze.json")
    for path, expected in frozen["files"].items():
        a.pin(path,expected)
    rubric=a.load("configs/focused_review_rubric.json")
    weights={r["id"]:r["weight"] for r in rubric["dimensions"]}
    a.same(sum(weights.values()),100,"score weights total 100","focused-scores")
    comparison=a.load("results/focused_revision/reviews/comparison.json")
    a.same(comparison["status"],"passed","score reconciliation passed","focused-scores")
    totals={"before":[],"after":[]}
    for reviewer in ("contribution","methods"):
        paired=next(row for row in comparison["reviewers"] if row["reviewer"]==reviewer)
        for stage in totals:
            path=f"results/focused_revision/reviews/{reviewer}_{stage}.json"
            result=a.load(path)
            a.pin(path,paired[stage]["review_sha256"])
            a.same(result["rubric_sha256"],comparison["rubric_sha256"],"same prospective rubric","focused-scores")
            dims={r["id"]:r for r in result["dimensions"]}
            a.same(set(dims),set(weights),"same six score dimensions","focused-scores")
            total=0
            for key, weight in weights.items():
                row=dims[key]; score=row["score"]
                a.check(0<=score<=5 and score*2==int(score*2),"score scale/step","focused-scores")
                a.same(row["weight"],weight,"fixed score weight","focused-scores")
                a.same(row["weighted_points"],score*weight/5,"weighted score arithmetic","focused-scores")
                total+=score*weight/5
            a.same(total,paired[stage]["total"],"per-reviewer score total","focused-scores")
            totals[stage].append(total)
            for source in result.get("reviewed_sources",result.get("sources",[])):
                a.pin(source["path"],source["sha256"])
        a.same(paired["change"],paired["after"]["total"]-paired["before"]["total"],"score difference","focused-scores")
    for stage, values in totals.items():
        a.same(comparison["mean"][stage],statistics.mean(values),"descriptive review mean","focused-scores")
    folder="results/focused_revision/diagnostics/"
    report=a.load(folder+"summary.json")
    run=a.load(folder+"run_manifest.json")
    raw=a.load(folder+"timings.json")
    protocol=a.load("configs/focused_diagnostic_protocol.json")
    a.same(report["status"],"passed","matched diagnostic experiment passed","focused-diagnostics")
    a.same(report["failures"],0,"diagnostic failures","focused-diagnostics")
    a.hashes_match(report["source_hashes"])
    a.same(run["source_hashes"],report["source_hashes"],"run and final source pins","focused-diagnostics")
    a.same(run["protocol"],protocol,"timed protocol fixed","focused-diagnostics")
    a.pin("configs/focused_diagnostic_protocol.json",report["protocol_sha256"])
    prepared=a.load("results/focused_revision/diagnostic_inputs/manifest.json")
    a.same(run["input_manifest"],prepared,"prepared inputs and run agree","focused-diagnostics")
    for name, expected in prepared["input_hashes"].items():
        a.pin("results/focused_revision/diagnostic_inputs/"+name+".json",expected)
    repeats=protocol["timing"]["measured_rounds"]
    a.same(len(raw),report["jobs"],"all raw jobs","focused-diagnostics")
    a.same(len(raw),7*2*2*(repeats+1),"complete planned diagnostic matrix","focused-diagnostics")
    a.same(sum(r["round"]>=0 for r in raw),report["measured_jobs"],"measured jobs","focused-diagnostics")
    a.same(sum(r["checks"] for r in raw),report["independent_checks"],"reported raw checker assertions","focused-diagnostics")
    a.same(len(report["cells"]),14,"seven models in two workloads","focused-diagnostics")
    seen=set()
    for row in raw:
        key=(row["name"],row["workload"],row["method"],row["round"])
        a.check(key not in seen,"unique diagnostic job","focused-diagnostics");seen.add(key)
        path=folder+f'r{row["round"]}_{row["name"]}_{row["workload"]}_{row["method"]}.json'
        child=a.load(path)
        stripped={k:v for k,v in row.items() if k not in {"round","phase","execution_position"}}
        a.same(child["timing"],stripped,"child raw timing matches combined rows","focused-diagnostics")
        a.same(row["failures"],0,"job checker failures","focused-diagnostics")
        a.same(sum(row["status_counts"].values()),row["requests"],"status/request denominator","focused-diagnostics")
        for clock in ("cpu_ns","wall_ns"):
            a.same(row["setup_plus_first"][clock],row["setup"][clock]+row["first_report"][clock],"first diagnostic setup accounting","focused-diagnostics")
            a.check(row["batch"][clock]>=row["setup"][clock],"batch includes setup","focused-diagnostics")
    for cell in report["cells"]:
        paired={}
        for method, saved_metrics in cell["methods"].items():
            rows=sorted((r for r in raw if r["name"]==cell["name"] and r["workload"]==cell["workload"] and r["method"]==method and r["round"]>=0),key=lambda r:r["round"])
            a.same([r["round"] for r in rows],list(range(repeats)),"all five measured rounds","focused-diagnostics")
            paired[method]=rows
            for field, values in saved_metrics.items():
                if isinstance(values,dict) and set(values)=={"cpu_ns","wall_ns"}:
                    for clock in values:
                        a.same(values[clock],statistics.median(r[field][clock] for r in rows),"matched timing median "+field,"focused-diagnostics")
            a.same(saved_metrics["process_peak_rss_kib"],statistics.median(r["process_peak_rss_kib"]["after_batch"] for r in rows),"absolute child memory median","focused-diagnostics")
            a.same(saved_metrics["output_bytes"],[r["output_bytes"] for r in rows],"all report sizes","focused-diagnostics")
            for row in rows:
                a.same(row["status_counts"],cell["status_counts"],"cell classification totals","focused-diagnostics")
        for clock, values in cell["paired_finite_minus_smt_batch_ns"].items():
            a.same(values,[x["batch"][clock]-y["batch"][clock] for x,y in zip(paired["finite_fibers"],paired["incremental_smt"])],"paired diagnostic deltas","focused-diagnostics")
        for repeat in range(-1,repeats):
            children=[a.load(folder+f'r{repeat}_{cell["name"]}_{cell["workload"]}_{m}.json')["diagnostics"] for m in protocol["methods"]]
            a.same(set(children[0]),set(children[1]),"same diagnosis population","focused-diagnostics")
            for key in children[0]:
                left,right=children[0][key],children[1][key]
                a.same(left["status"],right["status"],"same semantic status","focused-diagnostics")
                a.same(left["robust_masks"],right["robust_masks"],"same complete robust query family","focused-diagnostics")
    labels=[("procurement_identity","Procurement identity"),("procurement_strict","Procurement strict"),
            ("procurement_equivalent","Procurement equivalent"),("procurement_label_change","Procurement label change"),
            ("epcis_object_profile","EPCIS Object"),("epcis_aggregation_profile","EPCIS Aggregation"),
            ("epcis_transformation_profile","EPCIS Transformation")]
    cells={(c["name"],c["workload"]):c for c in report["cells"]}
    methods=("finite_fibers","incremental_smt")
    main=a.read("paper/manuscript_ieee_access_applied.md");supplement=a.read("paper/supplement_ieee_access_applied.md")
    expected_main=[];expected_s24=[];expected={25:[],26:[],27:[]}
    def ms(cell,field):
        return " / ".join(f'{cell["methods"][method][field]["cpu_ns"]/1e6:.3f}' for method in methods)
    def statuses(cell):
        return "/".join(f'{cell["status_counts"].get(status,0):,}' for status in ("safe","stale_verdict","insufficient"))
    for name,label in labels:
        unique,weighted=cells[name,"unique"],cells[name,"weighted"]
        expected_main.append([label]+[f'{cells[name,work]["methods"][method]["core_batch"]["cpu_ns"]/1e6:.3f}' for work in ("unique","weighted") for method in methods])
        expected_s24.append([label,f'{unique["requests"]:,}',statuses(unique),
                             f'{weighted["requests"]:,} / {weighted["diagnosed_classes"]:,}',statuses(weighted)])
        for work,short in (("unique","U"),("weighted","W")):
            cell=cells[name,work];heading=label+" "+short
            expected[25].append([heading]+[ms(cell,f) for f in ("core_setup","dependency_import","setup_plus_first")])
            expected[26].append([heading]+[ms(cell,f) for f in ("batch","core_batch","independent_raw_validation")])
            for method in methods:
                a.same(len(set(cell["methods"][method]["output_bytes"])),1,"constant per-cell serialized size","focused-paper")
            expected[27].append([heading,ms(cell,"serialization"),
                " / ".join(f'{int(cell["methods"][m]["process_peak_rss_kib"]):,}' for m in methods),
                " / ".join(f'{cell["methods"][m]["output_bytes"][0]:,}' for m in methods)])
    a.same(table_rows(main,10),expected_main,"main Table 10 all matched costs","focused-paper")
    a.same(table_rows(supplement,"S24"),expected_s24,"Table S24 diagnostic populations","focused-paper")
    for number,rows in expected.items():
        a.same(table_rows(supplement,f"S{number}"),rows,f"Table S{number} all matched cost values","focused-paper")
    a.same(sum(c["methods"]["finite_fibers"]["core_batch"]["cpu_ns"] < c["methods"]["incremental_smt"]["core_batch"]["cpu_ns"] for c in report["cells"]),14,"reported core batch median direction","focused-paper")
    a.same(sum(c["methods"]["incremental_smt"]["setup_plus_first"]["cpu_ns"] < c["methods"]["finite_fibers"]["setup_plus_first"]["cpu_ns"] for c in report["cells"]),10,"reported opposite first-report direction","focused-paper")
    figure=a.load("results/focused_revision/figure_manifest.json")
    a.pin(figure["source"],figure["source_sha256"])
    for item in figure["outputs"]:a.pin(item["path"],item["sha256"])
    a.facts["focused_diagnostics"]={"jobs":report["jobs"],"measured_jobs":report["measured_jobs"],"independent_checks_in_saved_runs":report["independent_checks"],"scope":"All saved timed jobs/medians/provenance and paired diagnostic statuses/robust query sets reconciled. Timings are not rerun; full raw diagnostic validity is checked by experiment oracles and independent tests."}
    a.facts["internal_scores"]={"before":comparison["mean"]["before"],"after":comparison["mean"]["after"],"scope":comparison["scope"]}

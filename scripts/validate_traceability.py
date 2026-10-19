#!/usr/bin/env python3
"""Check RTM registers against source inventories; does not call Jira or edit sources."""
from __future__ import annotations
import csv, re, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DOCS=ROOT/"docs/requirements"
REQ=DOCS/"traceability-requirements.csv"
STORY=DOCS/"traceability-stories.csv"
SRS=ROOT/"Dcos/FinSight_Software Requirements Specification (SRS).pdf"
BACKLOG=ROOT/"Dcos/FinSight_AI_Jira_Backlog_72_Stories_with_Acceptance_criteria.pdf"
TESTPLAN=ROOT/"Dcos/FinSight_AI_Sprint_1_Test_Plan_Management.txt"
EXECUTION=ROOT/"SPRINT_1_TEST_EXECUTION_STATUS.txt"
def pdf(path):
    return subprocess.run(["pdftotext","-layout",str(path),"-"],check=True,capture_output=True,text=True).stdout
def read(path):
    with path.open(newline="",encoding="utf-8") as f: return list(csv.DictReader(f))
def main():
    srs=pdf(SRS); backlog=pdf(BACKLOG)
    reqsrc=set(re.findall(r"\b(?:FR|NFR)-[A-Z0-9]+-\d{2}\b",srs))|set(re.findall(r"\bDIR-\d{2}\b",srs))
    alias_src=set(re.findall(r"\bFS-\d{2}-\d{2}\b",backlog))
    plan=TESTPLAN.read_text(encoding="utf-8")
    test_src=set(re.findall(r"^TEST CASE ID:\s*(TC_[A-Z0-9_]+)",plan,re.M))
    test_blocks=re.split(r"(?=^TEST CASE ID:)",plan,flags=re.M)
    test_aliases={}
    for block in test_blocks:
        tm=re.search(r"^TEST CASE ID:\s*(TC_[A-Z0-9_]+)",block,re.M)
        lm=re.search(r"^LINKED JIRA STORY:\s*(.*)$",block,re.M)
        if tm: test_aliases[tm.group(1)]=set(re.findall(r"FS-\d{2}-\d{2}",lm.group(1))) if lm else set()
    execution=EXECUTION.read_text(encoding="utf-8")
    req=read(REQ); stories=read(STORY); errors=[]
    reqids=[x["Requirement ID"] for x in req]; aliases=[x["Story alias"] for x in stories]
    if len(reqids)!=len(set(reqids)): errors.append("duplicate requirement rows")
    if set(reqids)!=reqsrc: errors.append(f"requirement inventory mismatch: missing {len(reqsrc-set(reqids))}, extra {len(set(reqids)-reqsrc)}")
    if len(aliases)!=len(set(aliases)): errors.append("duplicate story alias rows")
    if set(aliases)!=alias_src: errors.append(f"story inventory mismatch: missing {len(alias_src-set(aliases))}, extra {len(set(aliases)-alias_src)}")
    valid={"IMPLEMENTED — VERIFIED","PARTIAL","PLANNED","NOT IMPLEMENTED","BLOCKED","NOT ASSESSED"}
    for row in req:
        if row["Implementation status"] not in valid: errors.append(row["Requirement ID"]+": invalid implementation status")
        if row["Implementation status"]=="IMPLEMENTED — VERIFIED" and not row["Evidence path/reference"].strip(" —"): errors.append(row["Requirement ID"]+": verified without evidence")
        for tid in re.findall(r"TC_[A-Z0-9_]+",row["Test case IDs"]):
            if tid not in test_src: errors.append(row["Requirement ID"]+": unknown test ID "+tid)
    for row in stories:
        if not re.fullmatch(r"FIN-\d+",row["Verified Jira issue key"]): errors.append(row["Story alias"]+": malformed Jira key")
        if row["Jira mapping verification"]!="LIVE JIRA VERIFIED 2026-10-19": errors.append(row["Story alias"]+": dated live lookup evidence missing")
        for tid in re.findall(r"TC_[A-Z0-9_]+",row["Test case IDs"]):
            if tid not in test_src: errors.append(row["Story alias"]+": unknown test ID "+tid)
    known_aliases=set(aliases)
    unlinked_tests=sorted(tid for tid,linked in test_aliases.items() if not (linked & known_aliases))
    if unlinked_tests: errors.append("source tests without a catalog story link: "+", ".join(unlinked_tests))
    sprint1=[x for x in stories if x["Four-sprint assignment"]=="Sprint 1"]
    if len(sprint1)!=23: errors.append(f"Sprint 1 story count is {len(sprint1)}, expected 23")
    if any(x["SRS references from Jira/test-plan mapping"].strip(" —") and not x["Verified Jira issue key"] for x in sprint1):
        errors.append("Sprint 1 story has SRS references but no Jira mapping")
    process=next((x for x in sprint1 if x["Story alias"]=="FS-11-09"),None)
    if not process or process["SRS references from Jira/test-plan mapping"]!="—":
        errors.append("FS-11-09 process-story no-SRS-ID exception is not explicit")
    for alias in ("FS-07-04","FS-08-04"):

        x=next((r for r in stories if r["Story alias"]==alias),None)
        if not x or x["Source release label"]!="Release 2 only": errors.append(alias+": Release 2-only label missing/changed")
    mapped=sum(bool(x["Source story aliases"].strip(" —")) for x in req)
    no_test=sum(not x["Test case IDs"].strip(" —") for x in req)
    missing=sorted(test_src-set(re.findall(r"^(TC_[A-Z0-9_]+) \| Status:",execution,re.M)))
    print(f"SRS requirement IDs: {len(reqids)}; source story aliases: {len(aliases)}; Sprint 1 source tests: {len(test_src)}")
    print(f"Requirements with Jira/test-plan story links: {mapped}; unmapped: {len(reqids)-mapped}; no linked Sprint 1 test: {no_test}")
    print(f"Source tests linked to a catalog story: {len(test_src)-len(unlinked_tests)}/{len(test_src)}")
    print(f"Sprint 1 stories: {len(sprint1)}; with SRS IDs: {sum(bool(x['SRS references from Jira/test-plan mapping'].strip(' —')) for x in sprint1)}; process-story exception: FS-11-09")
    print("Tests lacking explicit execution rows (source default NOT RUN): "+(", ".join(missing) if missing else "none"))
    print("Jira key shape and dated live-query marker checked; this offline script does not query Jira.")
    if errors:
        print("VALIDATION FAILED",file=sys.stderr)
        for e in errors: print("- "+e,file=sys.stderr)
        return 1
    print("VALIDATION PASS: inventories, test references, evidence fields, and Release 2 labels are consistent.")
    return 0
if __name__=="__main__": raise SystemExit(main())


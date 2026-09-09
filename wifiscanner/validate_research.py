import time
import json
import os
from wifiscanner.research import (
    DatabaseManager, EventBus, ResourceManager, ExperimentManager,
    ProjectManager, DatasetManager, ExperimentDesign, 
    IndependentVariable, DependentVariable, ControlledVariable,
    BenchmarkFramework, MLResearchPipeline, ExperimentState
)
from wifiscanner.research.features import WatchdogDetectorAdapter

class MockPacket:
    def __init__(self, f_type, f_subtype, time_sec):
        self.type = f_type
        self.subtype = f_subtype
        self.time = time_sec
        self.addr1 = "FF:FF:FF:FF:FF:FF"
        self.addr2 = "AA:BB:CC:DD:EE:FF"
        self.addr3 = "11:22:33:44:55:66"
    def haslayer(self, layer):
        if layer.__name__ == "Dot11": return True
        return False
    def getlayer(self, layer):
        return None
    def __getitem__(self, layer):
        if layer.__name__ == "Dot11": return self
        raise KeyError()
    def __len__(self):
        return 128

def run_validation():
    print("==================================================")
    print(" PHASE 7: END-TO-END RESEARCH VALIDATION PIPELINE ")
    print("==================================================")
    
    # 1. Initialize Platform
    db = DatabaseManager("sqlite:///research_validation.sqlite")
    db.initialize_schema()
    event_bus = EventBus(db)
    res_mgr = ResourceManager(db)
    exp_mgr = ExperimentManager(db, event_bus, res_mgr)
    pm = ProjectManager(db)
    dm = DatasetManager(db)
    ml_pipe = MLResearchPipeline(db)
    
    event_bus.start()

    # 2. Research Question & Hypothesis (Project)
    print("\\n[+] Creating Research Project...")
    proj_id = pm.create_project(
        name="Deauth Flood Detector Resilience",
        description="Evaluating the effectiveness of adaptive thresholding in IDS under simulated noisy conditions.",
        researcher="Dr. Arena",
        hypothesis="Adaptive thresholding maintains precision >0.90 while mitigating False Positives in noisy RF environments."
    )
    
    # 3. Experiment Design
    print("[+] Designing Experiment...")
    design = ExperimentDesign(hypothesis="Sensitivity parameter linearly correlates with TP rate.")
    design.add_iv(IndependentVariable("sensitivity", "IDS Sensitivity", str, ["low", "medium", "high"]))
    design.add_dv(DependentVariable("precision", "Detection Precision", float))
    design.add_cv(ControlledVariable("flood_rate", "Frames per second", int, 50))
    design.repetitions = 1
    matrix = design.generate_matrix()
    
    for trial in matrix:
        print(f"  -> Trial Group {trial['_group_id']}: sensitivity={trial['sensitivity']}")
    
    # 4. Resources & Execution (Simulating one trial: "medium" sensitivity)
    print("\\n[+] Executing Trial: Medium Sensitivity...")
    exp_id = exp_mgr.create_experiment(
        project_id=proj_id,
        title="Trial 2: Medium Sensitivity",
        researcher="Dr. Arena",
        config={"sensitivity": "medium", "flood_frames": 5},
        variables={"independent": "medium"}
    )
    exp_mgr.transition_state(exp_id, ExperimentState.RUNNING)
    
    # 5. Capture & Dataset Generation
    print("[+] Generating Synthetic Dataset & Ground Truth...")
    ds_id = dm.create_dataset(
        name="Synthetic Deauth Burst",
        source_type="SYNTHETIC",
        experiment_id=exp_id,
        meta={"frames": 10, "duration": 1.0}
    )
    
    # We will generate 10 frames: 4 benign, 6 malicious (deauths)
    events = []
    labels = []
    base_time = time.time()
    for i in range(1, 11):
        is_attack = i > 4
        pkt = MockPacket(0, 12 if is_attack else 8, base_time + (i * 0.1))
        evt_id = f"pkt-{i}"
        
        # Log to event bus
        event_bus.publish("Simulator", "frame.captured", {"len": 128}, experiment_id=exp_id, correlation_id=evt_id)
        
        events.append({"id": evt_id, "frame": pkt})
        
        # Ground Truth
        label = "Attack" if is_attack else "Benign"
        dm.add_ground_truth(ds_id, evt_id, label, 1.0, {"generator": "script"})
        labels.append({"ref": evt_id, "label": label})
        
    time.sleep(1.0) # wait for event bus flush
    
    # 6. Analysis, Detector & Benchmark
    print("\\n[+] Running BenchmarkFramework with WatchdogDetectorAdapter...")
    benchmark = BenchmarkFramework(labels)
    detector = WatchdogDetectorAdapter({"flood_frames": 5, "sensitivity": "medium"})
    
    metrics = benchmark.evaluate_detector(detector, events)
    
    # 7. Reproducibility & State
    exp_mgr.transition_state(exp_id, ExperimentState.COMPLETED)
    
    # 8. Report Generation
    print("\\n==================================================")
    print("                 RESEARCH REPORT                  ")
    print("==================================================")
    print(f"Project ID: {proj_id}")
    print(f"Experiment ID: {exp_id}")
    print(f"Dataset ID: {ds_id}")
    with db.session_scope() as s:
        from wifiscanner.research import Project
        hyp = s.query(Project).filter_by(id=proj_id).first().hypothesis
        print(f"Hypothesis: {hyp}")
    print(f"Independent Variable: Sensitivity = medium")
    print("-" * 50)
    print("Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.2f}")
    print(f"  Precision: {metrics['precision']:.2f}")
    print(f"  Recall:    {metrics['recall']:.2f}")
    print(f"  F1 Score:  {metrics['f1_score']:.2f}")
    print(f"  Latency:   {metrics['latency_seconds']:.6f} s")
    print(f"  Throughput: {metrics['events_per_second']:.2f} eps")
    print("-" * 50)
    
    with db.session_scope() as s:
        from wifiscanner.research import Experiment
        exp = s.query(Experiment).filter_by(id=exp_id).first()
        manifest = exp.reproducibility_manifest
        print("Reproducibility Manifest:")
        print(f"  OS: {manifest['environment']['os']}")
        print(f"  Python: {manifest['environment']['python_version']}")
        print(f"  Git Commit: {manifest['git']['commit']}")
    print("==================================================")
    
    event_bus.stop()

if __name__ == "__main__":
    run_validation()

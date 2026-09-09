import json
import html
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from wifiscanner.research import (
    DatabaseManager, ProjectManager, ExperimentManager, DatasetManager,
    Project, Experiment, Dataset, MLModel, MLModelVersion, EventLog, Resource
)

class ResearchUIHandler(BaseHTTPRequestHandler):
    def _send(self, content: str, status: int = 200, content_type: str = "text/html"):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _page(self, title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<head>
<title>{html.escape(title)} - Research Platform</title>
<style>
    body {{ font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 0; background: #f4f5f7; color: #333; }}
    .header {{ background: #2c3e50; color: #fff; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }}
    .header a {{ color: #fff; text-decoration: none; margin-left: 1rem; }}
    .container {{ padding: 2rem; max-width: 1200px; margin: 0 auto; }}
    .card {{ background: #fff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }}
    th {{ background: #f8f9fa; }}
    .btn {{ display: inline-block; padding: 0.5rem 1rem; background: #3498db; color: #fff; text-decoration: none; border-radius: 4px; }}
    .btn:hover {{ background: #2980b9; }}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h2>🔬 Wireless Cybersecurity Research Platform</h2>
        <div>
            <a href="/">Dashboard</a>
            <a href="/projects">Projects</a>
            <a href="/datasets">Datasets</a>
            <a href="/resources">Resources</a>
        </div>
    </div>
    <div class="container">
        {body}
    </div>
</body>
</html>"""

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        
        db = self.server.db
        
        if path == "/":
            return self._send(self._page("Dashboard", self._render_dashboard(db)))
        elif path == "/projects":
            return self._send(self._page("Projects", self._render_projects(db)))
        elif path == "/datasets":
            return self._send(self._page("Datasets", self._render_datasets(db)))
        elif path == "/resources":
            return self._send(self._page("Resources", self._render_resources(db)))
        elif path.startswith("/experiment/"):
            exp_id = path.split("/")[-1]
            return self._send(self._page("Experiment Detail", self._render_experiment(db, exp_id)))
            
        self._send("404 Not Found", 404)

    def _render_dashboard(self, db):
        with db.session_scope() as session:
            p_count = session.query(Project).count()
            e_count = session.query(Experiment).count()
            d_count = session.query(Dataset).count()
            r_count = session.query(Resource).count()
            
        return f"""
        <div class="card">
            <h3>System Overview</h3>
            <div style="display: flex; gap: 2rem;">
                <div><h2>{p_count}</h2><p>Projects</p></div>
                <div><h2>{e_count}</h2><p>Experiments</p></div>
                <div><h2>{d_count}</h2><p>Datasets</p></div>
                <div><h2>{r_count}</h2><p>Lab Resources</p></div>
            </div>
        </div>
        """

    def _render_projects(self, db):
        with db.session_scope() as session:
            projects = session.query(Project).all()
            rows = ""
            for p in projects:
                rows += f"<tr><td>{p.name}</td><td>{p.researcher or 'N/A'}</td><td>{len(p.experiments)}</td></tr>"
                
        return f"""
        <div class="card">
            <h3>Research Projects</h3>
            <table>
                <tr><th>Project Name</th><th>Researcher</th><th>Experiments</th></tr>
                {rows}
            </table>
        </div>
        """

    def _render_datasets(self, db):
        with db.session_scope() as session:
            datasets = session.query(Dataset).all()
            rows = ""
            for d in datasets:
                rows += f"<tr><td>{d.name}</td><td>{d.source_type}</td><td>{d.version}</td><td>{d.checksum or 'N/A'}</td></tr>"
                
        return f"""
        <div class="card">
            <h3>Dataset Manager</h3>
            <table>
                <tr><th>Name</th><th>Source</th><th>Version</th><th>Checksum</th></tr>
                {rows}
            </table>
        </div>
        """

    def _render_resources(self, db):
        with db.session_scope() as session:
            resources = session.query(Resource).all()
            rows = ""
            for r in resources:
                caps = ", ".join(r.capabilities) if r.capabilities else "None"
                rows += f"<tr><td>{r.id}</td><td>{r.resource_type}</td><td>{caps}</td><td>{r.state.name}</td></tr>"
                
        return f"""
        <div class="card">
            <h3>Laboratory Resources</h3>
            <table>
                <tr><th>Resource ID</th><th>Type</th><th>Capabilities</th><th>State</th></tr>
                {rows}
            </table>
        </div>
        """

    def _render_experiment(self, db, exp_id):
        with db.session_scope() as session:
            exp = session.query(Experiment).filter_by(id=exp_id).first()
            if not exp:
                return "<p>Experiment not found.</p>"
            
            evts = session.query(EventLog).filter_by(experiment_id=exp_id).order_by(EventLog.timestamp.desc()).limit(50).all()
            evt_rows = ""
            for e in evts:
                evt_rows += f"<tr><td>{e.timestamp}</td><td>{e.source}</td><td>{e.event_type}</td><td>{e.severity}</td></tr>"
                
        return f"""
        <div class="card">
            <h3>Experiment: {exp.title}</h3>
            <p>Status: <strong>{exp.state.name}</strong></p>
            <p>Variables: <pre>{json.dumps(exp.variables, indent=2)}</pre></p>
        </div>
        <div class="card">
            <h3>Event Timeline</h3>
            <table>
                <tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Severity</th></tr>
                {evt_rows}
            </table>
        </div>
        """

def start_ui_server(db_path: str, bind: str, port: int):
    db = DatabaseManager(db_path)
    db.initialize_schema()
    
    server = HTTPServer((bind, port), ResearchUIHandler)
    server.db = db
    print(f"Research UI listening on http://{bind}:{port}")
    server.serve_forever()

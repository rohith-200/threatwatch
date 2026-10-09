"use client";
import { FormEvent, useState } from "react";

type Step = { step: string; status: "idle" | "running" | "done"; message: string };
const initialSteps: Step[] = ["ingest","osv","ghsa","kev","semgrep","score","advice","save"].map(step => ({ step, status: "idle", message: "Waiting" }));
const labels: Record<string,string> = { ingest:"Repository intake", osv:"OSV vulnerability match", ghsa:"GitHub advisories", kev:"KEV + EPSS signals", semgrep:"Semgrep code scan", score:"Risk prioritization", advice:"AI safety advice", save:"Report saved" };

export default function Home() {
  const [repo, setRepo] = useState("https://github.com/rohith-200/acme-checkout-api");
  const [days, setDays] = useState("30");
  const [steps, setSteps] = useState(initialSteps);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function analyze(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(""); setAnalysisId(null);
    setSteps(initialSteps.map(s => ({ ...s })));
    try {
      const res = await fetch("/api/analyze", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({ repoUrl: repo, lookbackDays: Number(days) }) });
      if (!res.ok || !res.body) throw new Error((await res.text()) || "Could not start analysis");
      const reader = res.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
      while (true) { const { value, done } = await reader.read(); if (done) break; buffer += decoder.decode(value, {stream:true});
        const chunks = buffer.split("\n\n"); buffer = chunks.pop() || "";
        for (const chunk of chunks) { const line = chunk.split("\n").find(x => x.startsWith("data: ")); if (!line) continue; const event = JSON.parse(line.slice(6));
          if (event.type === "progress") setSteps(prev => prev.map(s => s.step === event.step ? { ...s, status:event.status, message:event.message } : s));
          if (event.type === "result") setAnalysisId(event.analysisId);
          if (event.type === "error") throw new Error(event.message);
        }
      }
    } catch (err) { setError(err instanceof Error ? err.message : "Analysis failed"); } finally { setBusy(false); }
  }

  return <main className="shell">
    <nav><div className="brand"><span className="brandMark">◈</span> threat<span>watch</span></div><div className="navLinks"><a className="active">Overview</a><a>Threat feed</a><a>Docs</a><button className="avatar">TW</button></div></nav>
    <section className="hero"><div className="eyebrow"><i/> LIVE DEFENSE INTELLIGENCE</div><h1>Know what can hurt<br/><em>your code next.</em></h1><p className="lede">ThreatWatch continuously checks your repository against fresh advisories, exploit signals, and code-level evidence—then explains exactly what to fix.</p>
      <form className="scanCard" onSubmit={analyze}><div className="scanTop"><div><label>Repository URL</label><input value={repo} onChange={e=>setRepo(e.target.value)} placeholder="https://github.com/owner/repository" /></div><div className="window"><label>Lookback</label><select value={days} onChange={e=>setDays(e.target.value)}><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option></select></div><button disabled={busy}>{busy ? "Scanning…" : "Start scan  →"}</button></div><div className="hint"><span>⌁</span> Public GitHub repositories only · No source code leaves your environment</div></form>
    </section>
    <section className="workspace"><div className="sectionTitle"><div><div className="eyebrow">ANALYSIS PIPELINE</div><h2>{analysisId ? "Scan complete" : "A clear path from signal to action"}</h2></div>{analysisId && <a className="reportLink" href={`/report/${analysisId}`}>Open full report ↗</a>}</div>
      <div className="pipeline">{steps.map((s,i)=><div className={`step ${s.status}`} key={s.step}><div className="stepNum">{s.status === "done" ? "✓" : String(i+1).padStart(2,"0")}</div><div><strong>{labels[s.step]}</strong><small>{s.message}</small></div>{i < steps.length-1 && <div className="connector"/>}</div>)}</div>
      {error && <div className="error">{error}</div>}
      <div className="featureGrid"><article><span className="icon cyan">◎</span><h3>Fresh by design</h3><p>OSV, GitHub Security Advisories, CISA KEV, and EPSS signals are checked on every scan.</p></article><article><span className="icon amber">⌁</span><h3>Evidence, not guesses</h3><p>Semgrep findings point to the exact file and line without exposing source code to AI.</p></article><article><span className="icon violet">✦</span><h3>Safe AI guidance</h3><p>AkashML explains the attack path and verifies every recommendation before it reaches you.</p></article></div>
    </section>
    <footer><span>THREATWATCH / CONTINUOUS REPOSITORY DEFENSE</span><span>Built for the Cyberdefense Hackathon</span></footer>
  </main>;
}

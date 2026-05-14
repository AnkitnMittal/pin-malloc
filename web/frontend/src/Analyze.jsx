import './Analyze.css';
import { useRef, useState } from 'react';
import axios from 'axios';
import Editor from '@monaco-editor/react';

const DEFAULT_CODE = `#include <stdlib.h>
int main() {
  int* p = (int*)malloc(64);
  return 0;
}`;

const editorOptions = {
  minimap: { enabled: false },
  fontSize: 16,
  automaticLayout: true,
  padding: { top: 20, bottom: 20 },
  scrollBeyondLastLine: false,
};

const stats = [
  ['Allocations', 'total_allocations'],
  ['Frees', 'total_frees'],
  ['Leaks', 'total_leaks', true],
  ['Bytes', 'total_bytes_allocated'],
];

export default function Analyze() {
  const editorRef = useRef(null);
  const monacoRef = useRef(null);

  const [code, setCode] = useState(DEFAULT_CODE);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { summary = {}, leaks = [] } = analysis?.report || {};

  const focusLine = (line) => {
    editorRef.current?.revealLineInCenter(line);
    editorRef.current?.setPosition({ lineNumber: line, column: 1 });
  };

  const setMarkers = (diagnostics = []) => {
    if (!editorRef.current || !monacoRef.current) return;

    monacoRef.current.editor.setModelMarkers(
      editorRef.current.getModel(),
      'memory-leaks',
      diagnostics.map(({ line, message }) => ({
        startLineNumber: line,
        endLineNumber: line,
        startColumn: 1,
        endColumn: 100,
        message,
        severity: monacoRef.current.MarkerSeverity.Error,
      })),
    );

    diagnostics[0] && focusLine(diagnostics[0].line);
  };

  const analyzeCode = async () => {
    setLoading(true);
    setError('');
    setAnalysis(null);

    try {
      const { data } = await axios.post('http://127.0.0.1:8000/analyze', {
        code,
      });

      if (!data.success)
        return setError(data.compile_error || data.runtime_error);

      setAnalysis(data);
      setMarkers(data.diagnostics);
    } catch {
      setError('Backend connection failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="analyze-page">
      <header className="header">
        <div>
          <h1>Memory Trace Analyzer</h1>
          <p>Intel PIN based runtime memory analysis</p>
        </div>

        <button
          className="analyze-btn"
          onClick={analyzeCode}
          disabled={loading}
        >
          {loading ? 'Running...' : 'Run Analysis'}
        </button>
      </header>

      <main className="main-layout">
        <section className="editor-section">
          <Editor
            height="100%"
            defaultLanguage="cpp"
            theme="vs-dark"
            value={code}
            onChange={(v) => setCode(v || '')}
            options={editorOptions}
            onMount={(editor, monaco) => {
              editorRef.current = editor;
              monacoRef.current = monaco;
            }}
          />
        </section>

        <section className="results-section">
          {error && (
            <div className="error-box">
              <pre>{error}</pre>
            </div>
          )}

          <div className="panel">
            <h2 className="section-title">Live Analysis</h2>

            <div className="stats-grid">
              {stats.map(([title, key, danger]) => (
                <StatCard
                  key={key}
                  title={title}
                  value={summary[key] || 0}
                  danger={danger}
                />
              ))}
            </div>
          </div>

          <div className="panel leak-panel">
            <h2 className="section-title">Leak Details</h2>

            {!leaks.length ? (
              <div className="success-box">No memory leaks detected.</div>
            ) : (
              <table className="leak-table">
                <thead>
                  <tr>
                    <th className="table-header">Line</th>
                    <th className="table-header">Size</th>
                    <th className="table-header">Function</th>
                  </tr>
                </thead>

                <tbody>
                  {leaks.map(({ line, size, function: fn }, i) => (
                    <tr
                      key={i}
                      className="leak-row"
                      onClick={() => focusLine(line)}
                    >
                      <td className="table-cell">
                        <div className="line-badge">{line}</div>
                      </td>

                      <td className="table-cell">
                        <div className="size-badge">{size} bytes</div>
                      </td>

                      <td className="table-cell">
                        <div className="function-badge">{fn}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

function StatCard({ title, value, danger }) {
  return (
    <div className="stat-card">
      <div className={`stat-value ${danger ? 'danger-text' : ''}`}>{value}</div>

      <div className="muted">{title}</div>
    </div>
  );
}

import { useRef, useState } from 'react';
import Editor from '@monaco-editor/react';
import { apiClient } from '../api/client';
import StatCard from '../components/StatCard';
import { DEFAULT_CODE, editorOptions, analyzeStats } from '../utils/constants';

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
    editorRef.current?.focus();
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

    if (diagnostics[0]) focusLine(diagnostics[0].line);
  };

  const analyzeCode = async () => {
    setLoading(true);
    setError('');
    setAnalysis(null);

    try {
      const { data } = await apiClient.post('/analyze', { code });

      if (!data.success) {
        return setError(data.compile_error || data.runtime_error);
      }

      setAnalysis(data);
      setMarkers(data.diagnostics);
    } catch {
      setError('Backend connection failed. Ensure the server is running on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='w-full min-h-[calc(100vh-65px)] p-6 flex flex-col bg-[#020617] bg-[radial-gradient(circle_at_top_left,#172554_0%,transparent_30%),radial-gradient(circle_at_bottom_right,#0f172a_0%,transparent_30%)]'>
      <header className='flex flex-col xl:flex-row justify-between items-start xl:items-center mb-6 gap-5'>
        <div>
          <h1 className='text-white font-extrabold text-[42px] xl:text-[56px] tracking-tight leading-tight'>Memory Trace Analyzer</h1>
          <p className='mt-1.5 text-lg text-slate-400'>Intel PIN based runtime memory analysis</p>
        </div>

        <button
          className='border-none px-7 py-4 rounded-xl bg-linear-to-br from-blue-500 to-blue-400 text-white font-bold text-base shadow-[0_10px_30px_rgba(59,130,246,0.35)] hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-70 disabled:cursor-not-allowed'
          onClick={analyzeCode}
          disabled={loading}
        >
          {loading ? 'Running Analysis...' : 'Run Analysis'}
        </button>
      </header>

      <main className='flex-1 grid grid-cols-1 xl:grid-cols-[1.65fr_0.95fr] gap-6 items-start'>
        <section className='h-175 xl:h-[calc(100vh-180px)] p-3.5 bg-[#081226] border border-white/10 shadow-[0_10px_40px_rgba(0,0,0,0.45)] rounded-[28px] [&>div]:h-full [&>div]:overflow-hidden [&>div]:rounded-2xl'>
          <Editor
            defaultLanguage='cpp'
            theme='vs-dark'
            value={code}
            onChange={(v) => setCode(v || '')}
            options={editorOptions}
            onMount={(editor, monaco) => {
              editorRef.current = editor;
              monacoRef.current = monaco;
            }}
          />
        </section>

        <section className='flex flex-col gap-5'>
          {error && (
            <div className='p-4 rounded-xl max-h-60 overflow-auto text-red-200 bg-red-900/40 border border-red-500/40'>
              <pre className='whitespace-pre-wrap leading-relaxed font-mono text-sm'>{error}</pre>
            </div>
          )}

          <div className='p-6 rounded-[28px] bg-[#081226] border border-white/10 shadow-[0_8px_30px_rgba(0,0,0,0.35)]'>
            <h2 className='text-2xl font-bold text-center mb-5 text-white'>Live Analysis</h2>
            <div className='grid grid-cols-1 sm:grid-cols-2 gap-4'>
              {analyzeStats.map(([title, key, danger]) => (
                <StatCard key={key} title={title} value={summary[key] || 0} danger={danger} theme='dark' />
              ))}
            </div>
          </div>

          <div className='p-6 rounded-[28px] bg-[#081226] border border-white/10 shadow-[0_8px_30px_rgba(0,0,0,0.35)] overflow-hidden'>
            <h2 className='text-2xl font-bold text-center mb-5 text-white'>Leak Details</h2>

            {!leaks.length ? (
              <div className='p-4 rounded-xl text-center text-[15px] text-green-200 bg-green-900/30 border border-green-500/40'>
                {analysis ? 'No memory leaks detected.' : 'Run analysis to view detailed memory traces.'}
              </div>
            ) : (
              <div className='overflow-x-auto'>
                <table className='w-full border-collapse'>
                  <thead>
                    <tr className='border-b border-white/10'>
                      <th className='p-3 text-left text-[13px] uppercase tracking-wider text-slate-400'>Line</th>
                      <th className='p-3 text-left text-[13px] uppercase tracking-wider text-slate-400'>Size</th>
                      <th className='p-3 text-left text-[13px] uppercase tracking-wider text-slate-400'>Function</th>
                    </tr>
                  </thead>
                  <tbody>
                    {leaks.map(({ line, size, function: fn }, i) => (
                      <tr key={i} className='cursor-pointer transition-colors duration-200 hover:bg-blue-500/10 group' onClick={() => focusLine(line)}>
                        <td className='p-3 border-b border-white/5'>
                          <span className='inline-flex items-center justify-center min-w-8 h-8 rounded-lg bg-white/5 font-mono text-sm group-hover:bg-blue-500/20 group-hover:text-blue-300'>
                            {line}
                          </span>
                        </td>
                        <td className='p-3 border-b border-white/5 text-[14px]'>
                          <span className='text-slate-300'>{size} bytes</span>
                        </td>
                        <td className='p-3 border-b border-white/5'>
                          <span className='font-mono text-sm text-slate-400 bg-white/5 px-2 py-1 rounded'>{fn}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

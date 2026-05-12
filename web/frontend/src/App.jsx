import './App.css';

import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

export default function App() {
  const [reports, setReports] = useState([]);
  const [selectedTest, setSelectedTest] = useState(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/reports').then(({ data }) => {
      const sorted = data.sort(
        (a, b) => b.data.summary.total_leaks - a.data.summary.total_leaks,
      );

      setReports(sorted);
      setSelectedTest(sorted[0]);
    });
  }, []);

  const filteredReports = useMemo(
    () =>
      reports.filter((r) =>
        r.test_name.toLowerCase().includes(search.toLowerCase()),
      ),
    [reports, search],
  );

  const stats = useMemo(
    () =>
      reports.reduce(
        (acc, r) => {
          const s = r.data.summary;

          acc.tests++;
          acc.allocations += s.total_allocations;
          acc.frees += s.total_frees;
          acc.leaks += s.total_leaks;

          return acc;
        },
        {
          tests: 0,
          allocations: 0,
          frees: 0,
          leaks: 0,
        },
      ),
    [reports],
  );

  const chartData = filteredReports.map((r) => ({
    name: r.test_name,
    leaks: r.data.summary.total_leaks,
  }));

  const detail = selectedTest?.data;
  const summary = detail?.summary;

  return (
    <div className="page">
      <div className="container">
        <div className="header">
          <h1>Memory Trace Dashboard</h1>

          <p>Dynamic memory analysis reports from Intel PIN instrumentation</p>
        </div>

        <div className="stats-grid">
          <StatCard title="Tests" value={stats.tests} />

          <StatCard title="Allocations" value={stats.allocations} />

          <StatCard title="Frees" value={stats.frees} />

          <StatCard title="Leaks" value={stats.leaks} danger />
        </div>

        <div className="main-grid">
          <div className="panel">
            <h2 className="section-title">Test Cases</h2>

            <input
              type="text"
              placeholder="Search tests..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />

            <div className="test-list">
              {filteredReports.map((r) => {
                const leaks = r.data.summary.total_leaks;

                const active = selectedTest?.test_name === r.test_name;

                return (
                  <div
                    key={r.test_name}
                    onClick={() => setSelectedTest(r)}
                    className={`test-item ${active ? 'active' : ''}`}
                  >
                    <div className="row">
                      <strong>{r.test_name}</strong>

                      <div
                        className={`dot ${
                          leaks > 0 ? 'danger-dot' : 'success-dot'
                        }`}
                      />
                    </div>

                    <small className="muted">leaks: {leaks}</small>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="right-panel">
            <div className="panel">
              <h2 className="section-title">Leak Distribution</h2>

              <div className="chart-container">
                <ResponsiveContainer>
                  <BarChart data={chartData}>
                    <CartesianGrid stroke="#e5e7eb" />

                    <XAxis dataKey="name" />

                    <YAxis />

                    <Tooltip />

                    <Bar dataKey="leaks" fill="#ef4444" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="panel">
              <div className="detail-header">
                <h2 className="section-title">{selectedTest?.test_name}</h2>

                <p className="muted">Detailed memory trace statistics</p>
              </div>

              {summary && (
                <>
                  <div className="mini-grid">
                    <MiniStat
                      label="Allocations"
                      value={summary.total_allocations}
                    />

                    <MiniStat label="Frees" value={summary.total_frees} />

                    <MiniStat
                      label="Leaks"
                      value={summary.total_leaks}
                      danger
                    />

                    <MiniStat
                      label="Bytes"
                      value={`${(summary.total_bytes_allocated / 1024).toFixed(
                        2,
                      )} KB`}
                    />
                  </div>

                  <h3 className="leak-title">Leak Details</h3>

                  {detail.leaks.length === 0 ? (
                    <div className="success-box">No memory leaks detected.</div>
                  ) : (
                    <table className="leak-table">
                      <thead>
                        <tr>
                          <TH>Address</TH>
                          <TH>Size</TH>
                          <TH>Function</TH>
                        </tr>
                      </thead>

                      <tbody>
                        {detail.leaks.map((leak, idx) => (
                          <tr key={idx}>
                            <TD>{leak.address}</TD>

                            <TD>{leak.size}</TD>

                            <TD>{leak.function}</TD>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>
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

function MiniStat({ label, value, danger }) {
  return (
    <div className="mini-stat">
      <div className={`mini-value ${danger ? 'danger-text' : ''}`}>{value}</div>

      <div className="muted">{label}</div>
    </div>
  );
}

function TH({ children }) {
  return <th className="table-header">{children}</th>;
}

function TD({ children }) {
  return <td className="table-cell">{children}</td>;
}

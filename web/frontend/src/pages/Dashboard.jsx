import { useEffect, useMemo, useState } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { apiClient } from '../api/client';
import StatCard from '../components/StatCard';
import MiniStat from '../components/MiniStat';
import { TH, TD } from '../components/TableComponents';

export default function Dashboard() {
  const [reports, setReports] = useState([]);
  const [selectedTest, setSelectedTest] = useState(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    apiClient.get('/reports').then(({ data }) => {
      const sorted = data.sort((a, b) => b.data.summary.total_leaks - a.data.summary.total_leaks);
      setReports(sorted);
      setSelectedTest(sorted[0]);
    });
  }, []);

  const filteredReports = useMemo(() => reports.filter((r) => r.test_name.toLowerCase().includes(search.toLowerCase())), [reports, search]);

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
        { tests: 0, allocations: 0, frees: 0, leaks: 0 },
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
    <div className='max-w-350 mx-auto py-10 px-8 max-sm:py-6 max-sm:px-4'>
      <div className='mb-10'>
        <h1 className='text-[42px] font-bold mb-2'>Memory Trace Dashboard</h1>
        <p className='text-gray-500'>Dynamic memory analysis reports from Intel PIN instrumentation</p>
      </div>

      <div className='grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-5 mb-10'>
        <StatCard title='Tests' value={stats.tests} theme='light' />
        <StatCard title='Allocations' value={stats.allocations} theme='light' />
        <StatCard title='Frees' value={stats.frees} theme='light' />
        <StatCard title='Leaks' value={stats.leaks} danger theme='light' />
      </div>

      <div className='grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6 items-start'>
        <div className='bg-white border border-gray-200 rounded-[18px] p-6 shadow-sm'>
          <h2 className='text-[22px] mb-4 font-semibold'>Test Cases</h2>
          <input
            type='text'
            placeholder='Search tests...'
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className='w-full p-3 rounded-lg border border-gray-300 mb-5 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all'
          />
          <div className='flex flex-col gap-2.5'>
            {filteredReports.map((r) => {
              const leaks = r.data.summary.total_leaks;
              const active = selectedTest?.test_name === r.test_name;
              return (
                <div
                  key={r.test_name}
                  onClick={() => setSelectedTest(r)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    active ? 'border-blue-600 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'
                  }`}
                >
                  <div className='flex justify-between items-center mb-1'>
                    <strong className='text-sm'>{r.test_name}</strong>
                    <div className={`w-2.5 h-2.5 rounded-full ${leaks > 0 ? 'bg-red-500' : 'bg-green-500'}`} />
                  </div>
                  <small className='text-gray-500 text-xs font-medium'>leaks: {leaks}</small>
                </div>
              );
            })}
          </div>
        </div>

        <div className='flex flex-col gap-6'>
          <div className='bg-white border border-gray-200 rounded-[18px] p-6 shadow-sm'>
            <h2 className='text-[22px] mb-6 font-semibold'>Leak Distribution</h2>
            <div className='w-full h-80'>
              <ResponsiveContainer>
                <BarChart data={chartData}>
                  <CartesianGrid stroke='#e5e7eb' vertical={false} />
                  <XAxis dataKey='name' axisLine={false} tickLine={false} />
                  <YAxis axisLine={false} tickLine={false} />
                  <Tooltip
                    cursor={{ fill: '#f3f4f6' }}
                    contentStyle={{
                      borderRadius: '8px',
                      border: 'none',
                      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                    }}
                  />
                  <Bar dataKey='leaks' fill='#ef4444' radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className='bg-white border border-gray-200 rounded-[18px] p-6 shadow-sm'>
            <div className='mb-6'>
              <h2 className='text-[22px] font-semibold'>{selectedTest?.test_name}</h2>
              <p className='text-gray-500'>Detailed memory trace statistics</p>
            </div>

            {summary && (
              <>
                <div className='grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8'>
                  <MiniStat label='Allocations' value={summary.total_allocations} />
                  <MiniStat label='Frees' value={summary.total_frees} />
                  <MiniStat label='Leaks' value={summary.total_leaks} danger />
                  <MiniStat label='Bytes' value={`${(summary.total_bytes_allocated / 1024).toFixed(2)} KB`} />
                </div>

                <h3 className='text-lg font-semibold mb-4'>Leak Details</h3>
                {detail.leaks.length === 0 ? (
                  <div className='p-4 rounded-lg bg-green-50 text-green-800 border border-green-200 text-center font-medium'>No memory leaks detected.</div>
                ) : (
                  <div className='overflow-x-auto rounded-lg border border-gray-200'>
                    <table className='w-full border-collapse'>
                      <thead>
                        <tr className='bg-gray-50 border-b border-gray-200'>
                          <TH>Address</TH>
                          <TH>Size</TH>
                          <TH>Function</TH>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.leaks.map((leak, idx) => (
                          <tr key={idx} className='border-b border-gray-100 last:border-0 hover:bg-gray-50'>
                            <TD className='font-mono text-xs'>{leak.address}</TD>
                            <TD>{leak.size} bytes</TD>
                            <TD className='font-mono text-xs'>{leak.function}</TD>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

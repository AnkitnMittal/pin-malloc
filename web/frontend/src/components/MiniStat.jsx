export default function MiniStat({ label, value, danger }) {
  return (
    <div className='bg-gray-50 border border-gray-200 rounded-xl p-4'>
      <div className={`text-2xl font-bold mb-1.5 ${danger && value > 0 ? 'text-red-600' : 'text-gray-900'}`}>{value}</div>
      <div className='text-gray-500 text-sm font-medium'>{label}</div>
    </div>
  );
}

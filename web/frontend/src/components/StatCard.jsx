export default function StatCard({ title, value, danger, theme = 'light' }) {
  if (theme === 'dark') {
    return (
      <div className='flex flex-col items-center justify-center py-7 px-5 rounded-[22px] bg-[#0f1b34] border border-transparent transition-all duration-200 hover:-translate-y-1 hover:border-blue-500/35 group'>
        <div className={`text-4xl font-extrabold mb-2.5 ${danger && value > 0 ? 'text-red-500' : 'text-white'}`}>{value}</div>
        <div className='text-[15px] text-slate-400 font-medium group-hover:text-slate-300'>{title}</div>
      </div>
    );
  }

  return (
    <div className='bg-white border border-gray-200 rounded-2xl p-7 shadow-sm'>
      <div className={`text-[34px] font-bold mb-2 ${danger && value > 0 ? 'text-red-600' : 'text-gray-900'}`}>{value}</div>
      <div className='text-gray-500 font-medium'>{title}</div>
    </div>
  );
}
